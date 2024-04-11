package utils

import (
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/term"
)

type Metadata struct {
	Hashing_algorithm              string
	Symmetric_encryption_algorithm string
	Pbkdf2_iteration_count         int
	Encrypt_util_version           int
	Hashing_Salt                   []byte
}

type BinaryStruct struct {
	Metadata       Metadata
	MetadataSize   int
	Hmac           []byte
	HmacSize       int    // need this for the binary output to be of fix sized
	Ciphertext     []byte //block cipher encrypted covering (plain text + IV)
	CiphertextSize int
}

func DebugEncodedKey(key []byte) {
	fmt.Println(hex.EncodeToString(key))
}

func GetComplexPassword() string {
	fmt.Println("Password:: ")
	password_bytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}

	password := string(password_bytes)
	return strings.TrimSpace(password)
}
