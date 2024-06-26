package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"hash"
	"os"
	"runtime"
	"strings"

	"github.com/mergermarket/go-pkcs7"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"synarcs.com/css577/utils"
)

type IDecryptUtil interface {
	getKeySize() int
	readBinary(encrpt_file_name string)
	genRandBytes(bytelength int) []byte
	deriveArgonMasterKey()
	deriveArgonEncHmacKeys()
	deriveMasterKey()
	deriveHmacEncKeys()
	validateHmac() bool
	desDecrypt()
	aesDecrypt()
	writeDecryptedText(encrpt_file_name string)
	debugInputParamsMetadata(metadata *utils.Metadata)
	getbinaryBufferRead() utils.BinaryStruct
}

// the main util used to hold info for the decrypt tool
type DecryptUtil struct {
	binaryBufferRead utils.BinaryStruct

	// all the keys derived
	hmac_key       []byte
	encryption_key []byte
	master_key     []byte

	// hmac for message integrity over the decrypted content
	hmac_integrity_code []byte

	// synmmetric cipher chaining mode
	block_cipher_mode string // different block modes aes-cbc, aes-cfb,
	decryptedContnet  []byte
	iv                []byte
}

// since it uses pbkdf2 with a fixed length for different hashing algoritgh
// matching the collusiona and hash strength of underlying hashing alg, the keySize should match the size of underlying
// symmetric encryption algorithm
// from NIST guidelenes irrespective of hashing algorithm its secure to keep the salt size 16 bytes
func (dec *DecryptUtil) getKeySize() int {
	switch dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm {
	case "des3-3k-cbc", "des3-3k-cfb":
		return (192 / (1 << 3)) * 2 // (56 bits + 6 bits parity) * 3
	case "aes-128-cbc", "aes-128-cfb", "aes-128-gcm":
		return ((1 << 7) / (1 << 3)) * 2 // aes key size (bits) / 1 byte size (pbkdf2 go requires key in bytes)
	case "aes-256-cbc", "aes-256-cfb", "aes-256-gcm":
		return ((1 << 8) / (1 << 3)) * 2
	default:
		panic("Error the algorithm is not supported by Enc Util")
	}
}

const (
	debug  bool = false
	stdout bool = false
)

func (dec *DecryptUtil) getbinaryBufferRead() utils.BinaryStruct {
	return dec.binaryBufferRead
}

/*
read the binary encrypted file
The code expects the read binary to be of go binary serialized
*/
func (dec *DecryptUtil) readBinary(encrpt_file_name string) {
	ff, err := os.Open(encrpt_file_name)
	if err != nil {
		panic(err)
	}
	defer ff.Close()
	decoder := gob.NewDecoder(ff)
	var binaryStruct utils.BinaryStruct
	if debug {
		fmt.Println(binaryStruct)
	}
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

/*
Experimental method I wrote to learn and explore more with argon (Argon2i) based
time=3, and memory=32*1024
Number of threads: Number of avaialaible CPU cores
Generate the master key back for decryption purpose
*/
func (dec *DecryptUtil) deriveArgonMasterKey() {
	salt := dec.binaryBufferRead.Metadata.Hashing_Salt // keeping this same as aes block size considering the stength to be of (1 << 16)  bits
	password := utils.GetComplexPassword("decrypt")

	var masterKey []byte
	cpuCount := runtime.NumCPU()
	keyLength := dec.getKeySize()

	masterKey = argon2.Key([]byte(password), salt, 3, 32*(1<<10), uint8(cpuCount), uint32(keyLength))
	dec.master_key = masterKey[:len(masterKey)/2]
	if debug {
		fmt.Println("salt is ::")
		utils.DebugEncodedKey(salt)
		utils.DebugEncodedKey(dec.master_key)
	}
}

/*
Experimental method I wrote to learn and explore more with argon (Argon2i) based mem
time=3, and memory=32*1024
Number of threads: Number of avaialaible CPU cores
Generate the hmac  key and encryption key back for decryption purpose
*/
func (dec *DecryptUtil) deriveArgonEncHmacKeys() {
	saltString_enc := utils.SaltString_enc
	saltString_hmac := utils.SaltString_hmac

	var hmac_key []byte
	var enc_key []byte
	cpuCount := runtime.NumCPU()

	keySize := dec.getKeySize()
	hmac_key = argon2.Key(dec.master_key,
		saltString_hmac, 3, 3*(1<<10), uint8(cpuCount), uint32(keySize))
	enc_key = argon2.Key(dec.master_key,
		saltString_enc, 3, 3*(1<<10), uint8(cpuCount), uint32(keySize))

	dec.hmac_key = hmac_key[:len(hmac_key)/2]
	dec.encryption_key = enc_key[:len(enc_key)/2]

	if debug {
		fmt.Println("Hmac key")
		utils.DebugEncodedKey(dec.hmac_key)
		utils.DebugEncodedKey(dec.encryption_key)
	}
}

// Generate the master key back for decryption purpose using pbkdf2
func (dec *DecryptUtil) deriveMasterKey() {
	salt := dec.binaryBufferRead.Metadata.Hashing_Salt // keeping this same as aes block size considering the stength to be of (1 << 16)  bits
	password := utils.GetComplexPassword("decrypt")
	if debug {
		fmt.Println("Salt ::")
		utils.DebugEncodedKey(salt)
	}
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
	if debug {
		utils.DebugEncodedKey(masterKey)
	}
	dec.master_key = masterKey[:len(masterKey)/2]
}

// Generate the hmac  key and encryption key back for decryption purpose using pbkdf2
func (dec *DecryptUtil) deriveHmacEncKeys() {
	saltString_enc := utils.SaltString_enc
	saltString_hmac := utils.SaltString_hmac
	var hmac_key []byte
	var enc_key []byte
	switch dec.binaryBufferRead.Metadata.Hashing_algorithm {
	case "sha256":
		hmac_key = pbkdf2.Key(dec.master_key, saltString_hmac, 1, len(dec.master_key)*2, sha3.New256)
		enc_key = pbkdf2.Key(dec.master_key, saltString_enc, 1, len(dec.master_key)*2, sha3.New256)
	case "sha512":
		hmac_key = pbkdf2.Key(dec.master_key, saltString_hmac, 1, len(dec.master_key)*2, sha3.New512)
		enc_key = pbkdf2.Key(dec.master_key, saltString_enc, 1, len(dec.master_key)*2, sha3.New512)
	default:
		fmt.Errorf("Algorithm Not Supported")
	}
	if debug {
		utils.DebugEncodedKey(hmac_key)
		utils.DebugEncodedKey(enc_key)
	}
	dec.hmac_key = hmac_key[:len(hmac_key)/2]
	dec.encryption_key = enc_key[:len(enc_key)/2]
}

// most important validate the hmac by first internally computing the hmac and comparing it with hmac found in the binary metadata
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

	// generate the hmac on decryption size the encryption IV + cipher text
	// validate theis with the hmac code the ecnryption tool dumped in the binary file
	message_integrity_content_check := append(dec.binaryBufferRead.Metadata.Encrypt_IV, dec.binaryBufferRead.Ciphertext...)

	hmac_hash.Write(message_integrity_content_check)
	message_integrity_mac := hmac_hash.Sum(nil)

	if debug {
		utils.DebugEncodedKey(message_integrity_mac)
		utils.DebugEncodedKey(dec.binaryBufferRead.Hmac)
	}

	return hmac.Equal(message_integrity_mac, dec.binaryBufferRead.Hmac)
}

// decrypt the des cipher content using the derived encryption keys
// same as mentioned in des encrypt des does not support gcm due to smaller block size
func (dec *DecryptUtil) desDecrypt() {
	block, err := des.NewTripleDESCipher(dec.encryption_key) // init the main 3des decryptor mode

	if err != nil {
		panic(err)
	}

	if strings.Contains(dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "cfb") {
		// cfb mode decryptor
		mode := cipher.NewCFBDecrypter(block, dec.binaryBufferRead.Metadata.Encrypt_IV) // init the CFB block chain mode
		plaintext := make([]byte, len(dec.binaryBufferRead.Ciphertext))
		// XORs each byte in the given plaintext with a byte from the ciphertext, write back the results into the plaintext
		mode.XORKeyStream(plaintext, dec.binaryBufferRead.Ciphertext)

		fmt.Println("Decrypting using DES CFB:: ")
		dec.decryptedContnet = plaintext
		if stdout {
			fmt.Println(string(plaintext))
		}

	} else if strings.Contains(dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "cbc") {
		// cbc mode decryptor
		decrypt := cipher.NewCBCDecrypter(block, dec.binaryBufferRead.Metadata.Encrypt_IV)
		plaintext := make([]byte, len(dec.binaryBufferRead.Ciphertext))

		// Decrypt using CBC mode for each blocks the first block require IV and further follow standard decryption as done in CBC
		// the output is written in plaintext
		decrypt.CryptBlocks(plaintext, dec.binaryBufferRead.Ciphertext)
		plaintext, err := pkcs7.Unpad(plaintext, block.BlockSize())
		if err != nil {
			panic(err.Error())
		}

		fmt.Println("Decrypting using DES CBC:: ")
		dec.decryptedContnet = plaintext
		if stdout {
			fmt.Println(string(plaintext))
		}
	}
}

// decrypt the aes cipher content using the derived encryption keys
func (dec *DecryptUtil) aesDecrypt() {
	if len(dec.binaryBufferRead.Ciphertext) < aes.BlockSize {
		panic("Error the encrypted content is too small for aes to decrypt")
	}

	block, err := aes.NewCipher(dec.encryption_key) // init the main aes cipher encyrption algorithm
	if err != nil {
		panic(err)
	}

	if strings.Contains(dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "gcm") {
		aesGcm, error := cipher.NewGCM(block) // init the GCM block mode chaining
		if error != nil {
			panic(error)
		}
		if len(dec.binaryBufferRead.Ciphertext) < aesGcm.NonceSize() {
			panic("Error the Cipher Text Size is too small considering nounce ")
		}

		// slice the cipher block extracting the nonce and the cipher payload for the text
		// with the unique crypto rand nonce considered for the use of nounce (1 << 2) * 3 size generations

		nonce, ciphertext := dec.binaryBufferRead.Metadata.Encrypt_IV, // encrypt Iv is the nonce passed during encyrption
			dec.binaryBufferRead.Ciphertext[:]

		// Open decrypts and authenticates ciphertext, authenticates the
		// additional data and, if successful, appends the resulting plaintext
		// to dst,
		// ideally the hmac with iv + ciphertext is not required  to be validated
		// since the gcm mode support auth Tag (which serve purpose of hmac)
		// and there is not requirement how cbc is doing to generate the hmac over (iv + ciphertext)
		// hmac is required for cbc because of its drawback to not provide explicit authentication or integrity to prevent tampering of message
		plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil)

		if err != nil {
			mess := fmt.Sprintf("Aes GCM :: %s", err.Error())
			panic(mess)
		}

		fmt.Println("Decrypting using AES GCM:: ")
		dec.decryptedContnet = plaintext
		if stdout {
			fmt.Println(string(plaintext))
		}
	} else if strings.Contains(dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "cfb") {
		mode := cipher.NewCFBDecrypter(block, dec.binaryBufferRead.Metadata.Encrypt_IV) // init the CFB block mode chaining
		plaintext := make([]byte, len(dec.binaryBufferRead.Ciphertext))
		// XORs each byte in the given plaintext with a byte from the ciphertext, write back the results into the plaintext
		mode.XORKeyStream(plaintext, dec.binaryBufferRead.Ciphertext)

		fmt.Println("Decrypting using AES CFB:: ")
		dec.decryptedContnet = plaintext
		if stdout {
			fmt.Println(string(plaintext))
		}

	} else if strings.Contains(dec.binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "cbc") {
		mode := cipher.NewCBCDecrypter(block, dec.binaryBufferRead.Metadata.Encrypt_IV) // init the CBC block mode chaining
		plaintext := make([]byte, len(dec.binaryBufferRead.Ciphertext))

		// Decrypt using CBC mode for each blocks the first block require IV and further follow standard decryption as done in CBC
		// the output is written in plaintext
		mode.CryptBlocks(plaintext, dec.binaryBufferRead.Ciphertext)

		// remove padding
		plaintext, err := pkcs7.Unpad(plaintext, block.BlockSize()) // remove padding using pkcs7 standards
		if err != nil {
			panic(err.Error())
		}

		fmt.Println("Decrypting using AES CBC:: ")
		dec.decryptedContnet = plaintext
		if stdout {
			fmt.Println(string(plaintext))
		}
	}
}

func (dec *DecryptUtil) writeDecryptedText(encrpt_file_name string) {
	decryptHandler := func(outputDecryptedFile string) {
		file, err := os.Create(outputDecryptedFile)
		if err != nil {
			panic(err.Error())
		}

		defer file.Close()
		bytesWritten, err := file.Write([]byte(dec.decryptedContnet))
		if err != nil {
			panic(err.Error())
		}
		fmt.Printf("Decrypted Content Wrote n bytes %d", bytesWritten)
	}
	outputDecryptedFile := strings.Replace(encrpt_file_name, "enc", "dec", 3)
	fmt.Println(encrpt_file_name, outputDecryptedFile)
	if _, err := os.Stat(outputDecryptedFile); err == nil {
		os.Remove(outputDecryptedFile)
		decryptHandler(outputDecryptedFile)
	} else if errors.Is(err, os.ErrNotExist) {
		decryptHandler(outputDecryptedFile)
	} else {
		panic(err.Error())
	}
}

func (dec *DecryptUtil) debugInputParamsMetadata(metadata *utils.Metadata) {
	fmt.Println("--- Hashing Algorithm --- ", metadata.Hashing_algorithm)
	fmt.Println("--- Encryption Algorithm --- ", metadata.Symmetric_encryption_algorithm)
	fmt.Println("--- KDF Interation Count  --- ", metadata.Pbkdf2_iteration_count)
	fmt.Println("--- using Argon Mode for KDF ---", metadata.Argon_Hash_Mode)
}

// main runner for the code
func main() {

	var decryptUtil IDecryptUtil = &DecryptUtil{}

	fmt.Println("//////// Decryption Tool Started //////// ")
	encrpt_file_name := utils.GetInputFileName("decrypt")

	decryptUtil.readBinary(encrpt_file_name)
	binaryBufferRead := decryptUtil.getbinaryBufferRead()
	decryptUtil.debugInputParamsMetadata(&binaryBufferRead.Metadata)

	if !binaryBufferRead.Metadata.Argon_Hash_Mode {
		decryptUtil.deriveMasterKey()
		decryptUtil.deriveHmacEncKeys()
	} else {
		fmt.Println("using Argon Mode for KDF")
		decryptUtil.deriveArgonMasterKey()
		decryptUtil.deriveArgonEncHmacKeys()
	}

	// gcm has its own authTag which can be used to validate it has nonce and no iv (although they can be used inter changebly) but the authTag can verify the integrity of the message
	if !decryptUtil.validateHmac() && !strings.Contains(binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "gcm") {
		err := "There is message tampering the Hmac coded did not match Error Integrity check broke..."
		panic(err)
	}

	if strings.HasPrefix(binaryBufferRead.Metadata.Symmetric_encryption_algorithm, "aes") {
		decryptUtil.aesDecrypt()
	} else {
		decryptUtil.desDecrypt()
	}

	decryptUtil.writeDecryptedText(encrpt_file_name)

	fmt.Printf("\n ////////  Decryption Completed //////")
}
