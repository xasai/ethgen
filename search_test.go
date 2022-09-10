package main

import "testing"

func Test_hexCharsEqual(t *testing.T) {
	if !hexCharsEqual(byte(0x55)) {
		t.Fatal("55 not equal")
	}
	if hexCharsEqual(byte(0x12)) {
		t.Fatal("0x12 equal")
	}
}
