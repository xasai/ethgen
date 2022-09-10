package main

import (
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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const _PASSWORD_ENV_VAR = "ETHGEN_PASSWD"

var (
	decryptFlag = flag.String("d", "", "decrypt file")

	caseInsensetive = flag.Bool("i", false, "case insesetive search")

	suffixes = []string{
		"dead",
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
		key, err := decryptAES(passwd, *decryptFlag)
		if err != nil {
			fmt.Printf("Error decrypting: %s", err.Error())
			os.Exit(1)
		}
		fmt.Printf("Private key: %x", key)
		os.Exit(0)
	}

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

		if explain, nice := isNice(addr); nice {

			fmt.Println(addr, ":", explain)

			encPrivateKey, err := encryptAES(passwd, crypto.FromECDSA(privateKey))
			if err != nil {
				fmt.Println("encryptAES", err.Error())
				continue
			}
			if err = os.MkdirAll(explain, os.ModeDir|0700); err != nil {
				fmt.Println("os.Mkdir", err.Error())
				continue
			}

			if err = os.WriteFile(filepath.Join(explain, addr.Hex()), encPrivateKey, 0400); err != nil {
				fmt.Println("os.WriteFile", err.Error())
				continue
			}
		}
	}
}

func isNice(addr common.Address) (explain string, nice bool) {

	var (
		first   = addr[0]
		second  = addr[1]
		prelast = addr[len(addr)-2]
		last    = addr[len(addr)-1]
	)

	if hexCharsEqual(first) &&
		first == second &&
		first == prelast &&
		first == last {
		return "0xAAAA..AAAA", true
	}

	if first == second &&
		first == prelast &&
		first == last {
		return "0x1C1C..1C1C", true
	}

	if first == second && (hexCharsEqual(first) && hexCharsEqual(second)) ||
		prelast == last && (hexCharsEqual(prelast) && hexCharsEqual(last)) {
		return "0xAAAA..1234|0x1234...AAAA", true
	}

	addrStr := addr.Hex()[2:]
	if *caseInsensetive {
		addrStr = strings.ToLower(addrStr)
	}

	for _, suffix := range suffixes {
		if strings.HasSuffix(addrStr, suffix) {
			return "suffix", true
		}
	}

	return "nothing found", false
}

// checks whether chars in hex equal
// like: 88 99 aa bb ... and so on
func hexCharsEqual(b byte) bool {
	return (b&0b11110000)>>4 == (b & 0b00001111)
}

func encryptAES(key, data []byte) ([]byte, error) {
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

func decryptAES(key []byte, path string) ([]byte, error) {
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
