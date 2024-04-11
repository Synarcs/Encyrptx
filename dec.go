package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"synarcs.com/css577/utils"
)

type DecryptUtil struct {
	binaryBufferRead utils.BinaryStruct

	// all the keys derived
	hmac_key       []byte
	encryption_key []byte
	master_key     []byte

	// hmac for message integrity over the decrypted content
	hmac_integrity_code []byte

	// synmmetric cipher chaining mode
	block_cipher_mode   string // different block modes aes-cbc, aes-cfb,
	aesdecryptedContnet []byte
	iv                  []byte
}

func (dec *DecryptUtil) getIv() []byte { return []byte("decrypt") }

func (dec *DecryptUtil) getKeySize() int {
	switch dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm {
	case "des3-2k":
		return 56 * 2
	case "des3-3k":
		return 56 * 3
	case "aes-128-cbc":
		return (1 << 7) / (1 << 3) // aes key size (bits) / 1 byte size (pbkdf2 go requires key in bytes)
	case "aes-256-cbc":
		return (1 << 8) / (1 << 3)
	default:
		panic("Error the algorithm is not supported by dec Util")
	}
}

var encrpt_file_name string = "input.enc"

func (dec *DecryptUtil) readBinary() {
	ff, err := os.Open(encrpt_file_name)
	if err != nil {
		panic(err)
	}
	defer ff.Close()
	decoder := gob.NewDecoder(ff)
	var binaryStruct utils.BinaryStruct
	err = decoder.Decode(&binaryStruct)
	fmt.Println(binaryStruct.Metadata)
	if err != nil {
		panic(err)
	}
	dec.binaryBufferRead = binaryStruct
}

// Used the crypto rand as agains math/rand which uses psuedo random number causing more collusion in the generated random output
func (dec *DecryptUtil) genRandBytes(bytelength int) []byte {
	randBytes := make([]byte, bytelength)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("error in generating crypto secured rand")
	}
	return randBytes
}

func (dec *DecryptUtil) deriveMasterKey() {
	salt := dec.binaryBufferRead.Metadata.Hashing_Salt // keeping this same as aes block size considering the stength to be of (1 << 16)  bits
	password := utils.GetComplexPassword()
	fmt.Println("Salt ::")
	utils.DebugEncodedKey(salt)
	var masterKey []byte
	keyLength := dec.getKeySize()
	fmt.Printf("Key Size Used for Algorithm :: %s size :: %d bytes \n", dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, keyLength)

	switch dec.binaryBufferRead.Metadata.Hashing_algorithm {
	case "sha256":
		masterKey = pbkdf2.Key([]byte(password), salt, int(dec.binaryBufferRead.Metadata.Pbkdf2_iteration_count),
			keyLength, sha3.New256)
		fmt.Println("Using Sha3 :: Using sha3-", dec.binaryBufferRead.Metadata.Hashing_algorithm)
	case "sha512":
		masterKey = pbkdf2.Key([]byte(password), salt, int(dec.binaryBufferRead.Metadata.Pbkdf2_iteration_count),
			keyLength, sha3.New512)
		fmt.Println("Using Sha3 :: Using ", dec.binaryBufferRead.Metadata.Hashing_algorithm)
	default:
		fmt.Errorf("Algorithm Not supported")
	}
	utils.DebugEncodedKey(masterKey)
	dec.master_key = masterKey
}

func (dec *DecryptUtil) deriveHmacEncKeys() {
	saltString_enc := []byte("encrption_fixed_str")
	saltString_hmac := []byte("hmac_fixed_str")
	var hmac_key []byte
	var enc_key []byte
	switch dec.binaryBufferRead.Metadata.Hashing_algorithm {
	case "sha256":
		hmac_key = pbkdf2.Key(dec.master_key, saltString_hmac, 1, len(dec.master_key), sha3.New256)
		enc_key = pbkdf2.Key(dec.master_key, saltString_enc, 1, len(dec.master_key), sha3.New256)
	case "sha512":
		hmac_key = pbkdf2.Key(dec.master_key, saltString_hmac, 1, len(dec.master_key), sha3.New512)
		enc_key = pbkdf2.Key(dec.master_key, saltString_enc, 1, len(dec.master_key), sha3.New512)
	default:
		fmt.Errorf("Algorithm Not Supported")
	}
	utils.DebugEncodedKey(hmac_key)
	utils.DebugEncodedKey(enc_key)
	dec.hmac_key = hmac_key
	dec.encryption_key = enc_key
}

func (dec *DecryptUtil) validateHmac() bool {

	var hmac_hash hash.Hash
	switch dec.binaryBufferRead.Metadata.Hashing_algorithm {
	case "sha256":
		hmac_hash = hmac.New(sha3.New256, dec.hmac_key)
	case "sha512":
		hmac_hash = hmac.New(sha3.New512, dec.hmac_key)
	default:
		fmt.Errorf("Algorithm not supported")
		panic("Error the algorithm for key sign not supported")
	}

	message_integrity_content_check := append(dec.binaryBufferRead.Metadata.Encrypt_IV_CBC, dec.binaryBufferRead.Ciphertext...)

	hmac_hash.Write(message_integrity_content_check)
	message_integrity_mac := hmac_hash.Sum(nil)

	fmt.Println(message_integrity_mac, dec.binaryBufferRead.Hmac)
	return hmac.Equal(message_integrity_mac, dec.binaryBufferRead.Hmac)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data is empty")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}

func (dec *DecryptUtil) aesDecrypt() {
	if len(dec.binaryBufferRead.Ciphertext) < aes.BlockSize {
		panic("Error the encrypted content is too small for aes to decrypt")
	}

	block, err := aes.NewCipher(dec.encryption_key)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCDecrypter(block, dec.binaryBufferRead.Metadata.Encrypt_IV_CBC) // gcm has the base main mode for nounce
	plaintext := make([]byte, len(dec.binaryBufferRead.Ciphertext))

	mode.CryptBlocks(plaintext, dec.binaryBufferRead.Ciphertext)

	buffer, err := pkcs7Unpad(plaintext)
	if err != nil { panic(err) }
	fmt.Println(string(buffer))
}

func main() {
	var decryptUtil *DecryptUtil = &DecryptUtil{}

	decryptUtil.readBinary()
	decryptUtil.deriveMasterKey()
	decryptUtil.deriveHmacEncKeys()

	if !decryptUtil.validateHmac() {
		err := "There is message tampering the Hmac coded did not match Error Integrity check broke..."
		panic(err)
	}

	decryptUtil.aesDecrypt()
}
