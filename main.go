package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const _PASSWORD_ENV_VAR = "ETHGEN_PASSWD"

var (
	decryptFlag = flag.String("d", "", "decrypt file")
	routines    = flag.Int("g", 20, "goroutines count")
	endian      = []string{
		"0000",
	}
	full = []string{
		"0x0000_0000",
		"",
		"",
	}
)

func main() {
	flag.Parse()
	passwdStr := os.Getenv(_PASSWORD_ENV_VAR)
	if passwdStr == "" {
		fmt.Println("specify ETHGEN_PASSWD to encrypt generated private keys")
		os.Exit(1)
	}
	os.Unsetenv(_PASSWORD_ENV_VAR)

	passwdHash := sha256.Sum256([]byte(passwdStr))
	passwd := passwdHash[:]

	if *decryptFlag != "" {
		key, err := decrypt(passwd, *decryptFlag)
		if err != nil {
			fmt.Printf("Error decrypting: %s", err.Error())
			os.Exit(1)
		}
		fmt.Printf("Private key: %x", key)
		os.Exit(0)
	}

	wg := sync.WaitGroup{}
	wg.Add(*routines)
	for i := 0; i < *routines; i++ {
		go func() {
			for {
				privateKey, err := crypto.GenerateKey()
				if err != nil {
					fmt.Println("GenerateKey error:", err.Error())
				}
				publicKey := privateKey.Public()
				publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
				if !ok {
					fmt.Println("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
					continue
				}
				addr := crypto.PubkeyToAddress(*publicKeyECDSA)

				if alias, nice := isPretty(addr); nice {
					fmt.Println(addr, "-", alias)
					encPrivateKey, err := encrypt(passwd, crypto.FromECDSA(privateKey))
					if err != nil {
						fmt.Println("encryptAES", err.Error())
						continue
					}
					if err = os.MkdirAll(alias, os.ModeDir|0700); err != nil {
						fmt.Println(alias, "os.Mkdir: ", err.Error())
						continue
					}

					if err = os.WriteFile(filepath.Join(alias, addr.Hex()), encPrivateKey, 0400); err != nil {
						fmt.Println("os.WriteFile", err.Error())
						continue
					}
				}
			}
		}()
	}
	wg.Wait()
}

func isPretty(addr common.Address) (alias string, nice bool) {
	var (
		begin = addr[:2]
		end   = addr[len(addr)-2:]
	)

	if hexCharsEqual(begin[0]) && begin[0] == begin[1] && bytes.Equal(begin, end) {
		return "0xAAAA..AAAA", true
	}

	shortForm := trimAddr(addr)
	for _, pattern := range full {
		if shortForm == pattern {
			return "full", true
		}
	}

	return "nothing found", false
}

func trimAddr(addr common.Address) string {
	// Convert the address to a string
	// Trim the first and last 4 characters
	hex := addr.Hex()
	prefix := hex[:8]
	suffix := hex[len(hex)-6:]
	return strings.ToLower(prefix + "_" + suffix)
}

// checks whether chars in hex equal
// like: 88 99 aa bb ... and so on
func hexCharsEqual(b byte) bool {
	return (b&0b11110000)>>4 == (b & 0b00001111)
}

func encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(key []byte, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, encrData := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	decrData, err := gcm.Open(nil, nonce, encrData, nil)
	if err != nil {
		return nil, err
	}

	return decrData, nil
}
