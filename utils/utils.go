package utils

import (
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/term"
)

var SaltString_enc []byte = []byte("encrption_fixed_str")
var SaltString_hmac []byte = []byte("hmac_fixed_str")

type Metadata struct {
	Hashing_algorithm              string
	Symmetric_encryption_algorithm string
	Pbkdf2_iteration_count         int
	Encrypt_util_version           int
	Hashing_Salt                   []byte
	Encrypt_IV                     []byte
	Argon_Hash_Mode                bool
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

func GetComplexPassword(mode string) string {
	if mode == "encrypt" {
		fmt.Println("Password for Encryption:: ")
	} else {
		fmt.Println("Password for Decryption:: ")
	}
	password_bytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}

	password := string(password_bytes)
	return strings.TrimSpace(password)
}

func GetInputFileName(mode string) string {
	if mode == "encrypt" {
		fmt.Println("Input PlainText FileName:: ")
	} else {
		fmt.Println("Input Encrypted FileName:: ")
	}
	var fileName string
	fmt.Scanf("%s", &fileName)

	return strings.TrimSpace(fileName)
}
