package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"hash"
	"os"
	"strings"

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
	case "des3-3k":
		return 192 / (1 << 3)
	case "aes-128-cbc", "aes-128-cfb", "aes-128-gcm":
		return (1 << 7) / (1 << 3) // aes key size (bits) / 1 byte size (pbkdf2 go requires key in bytes)
	case "aes-256-cbc", "aes-256-cfb", "aes-256-gcm":
		return (1 << 8) / (1 << 3)
	default:
		panic("Error the algorithm is not supported by Enc Util")
	}
}

const debug bool = false

func (dec *DecryptUtil) readBinary(encrpt_file_name string) {
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
		err := "The Encrypted Binary is tampered or corrupted considering byte order of Big Endian"
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

	message_integrity_content_check := append(dec.binaryBufferRead.Metadata.Encrypt_IV, dec.binaryBufferRead.Ciphertext...)

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

func (dec *DecryptUtil) desDecrypt() {
	block, err := des.NewTripleDESCipher(dec.encryption_key)

	if err != nil {
		panic(err)
	}

	decrypt := cipher.NewCBCDecrypter(block, dec.binaryBufferRead.Metadata.Encrypt_IV)
	plaintext := make([]byte, len(dec.binaryBufferRead.Ciphertext))

	decrypt.CryptBlocks(plaintext, dec.binaryBufferRead.Ciphertext)
	// buffer, err := pkcs7Unpad(plaintext)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext))
}

func (dec *DecryptUtil) aesDecrypt() {
	if len(dec.binaryBufferRead.Ciphertext) < aes.BlockSize {
		panic("Error the encrypted content is too small for aes to decrypt")
	}

	block, err := aes.NewCipher(dec.encryption_key)
	if err != nil {
		panic(err)
	}

	if strings.Contains(dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "gcm") {
		aesGcm, error := cipher.NewGCM(block)
		if error != nil {
			panic(error)
		}
		if len(dec.binaryBufferRead.Ciphertext) < aesGcm.NonceSize() {
			panic("Error the Cipher Text Size is too small considering nounce ")
		}

		// slice the cipher block extracting the nonce and the cipher payload for the text  
		// with the unique crypto rand nonce considered for the use of nounce (1 << 2) * 3 size generations 
		nonce, ciphertext := dec.binaryBufferRead.Ciphertext[:aesGcm.NonceSize()],
			dec.binaryBufferRead.Ciphertext[aesGcm.NonceSize():]
		plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			panic(err.Error())
		}

		fmt.Println("Decrypting using AES GCM:: ")
		fmt.Println(string(plaintext))
	} else if strings.Contains(dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "cfb") {
		mode := cipher.NewCFBDecrypter(block, dec.binaryBufferRead.Metadata.Encrypt_IV)
		plaintext := make([]byte, len(dec.binaryBufferRead.Ciphertext))
		mode.XORKeyStream(plaintext, dec.binaryBufferRead.Ciphertext)

		fmt.Println("Decrypting using AES CFB:: ")
		fmt.Println(string(plaintext))

	} else if strings.Contains(dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "cbc") {
		iv := dec.genRandBytes(aes.BlockSize)
		mode := cipher.NewCBCDecrypter(block, iv) // gcm has the base main mode for nounce
		plaintext := make([]byte, len(dec.binaryBufferRead.Ciphertext))

		mode.CryptBlocks(plaintext, dec.binaryBufferRead.Ciphertext)

		buffer, err := pkcs7Unpad(plaintext)
		if err != nil {
			panic(err)
		}
		fmt.Println("Decrypting using AES CBC:: ")
		fmt.Println(string(buffer))
	}
}

func main() {
	var decryptUtil *DecryptUtil = &DecryptUtil{}

	encrpt_file_name := utils.GetInputFileName()

	encrpt_file_name = encrpt_file_name + ".enc"
	decryptUtil.readBinary(encrpt_file_name)
	decryptUtil.deriveMasterKey()
	decryptUtil.deriveHmacEncKeys()

	if !decryptUtil.validateHmac() {
		err := "There is message tampering the Hmac coded did not match Error Integrity check broke..."
		panic(err)
	}

	if strings.HasPrefix(decryptUtil.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "aes") {
		decryptUtil.aesDecrypt()
	} else {
		decryptUtil.desDecrypt()
	}
}
