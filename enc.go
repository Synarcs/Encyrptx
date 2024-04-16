package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v2"
	"synarcs.com/css577/utils"
)

/*
Input Args Struct for the encryption tool
*/
type EncryptUtilInputArgs struct {
	Version int `yaml:"version"`

	// algorithm information
	Hashing_algorithm              string `yaml:"hashing_algorithm"`
	Symmetric_encryption_algorithm string `yaml:"symmetric_encryption_algorithm"`

	// iteration count for kdf using custom random secured rand salt
	Pbkdf2_iteration_count     int    `yaml:"pbkdf2_iteration_count"`
	Plain_text_file_name       string `yaml:"plain_text_file_name"`
	Encrypted_file_output_name string `yaml:"encrypted_file_output_name"`
	Argon_Hash_Mode            bool   `yaml:"argon_hash_mode"`
}

/*
Encrypt tool util struct
*/
type EncryptUtil struct {
	inputArgs *EncryptUtilInputArgs

	ciphertext []byte

	// all the keys
	hmac_key       []byte
	encryption_key []byte
	master_key     []byte

	// hmac for message integrity over the encrypted content
	hmac_integrity_code []byte

	// synmmetric cipher chaining mode
	block_cipher_mode string // different block modes aes-cbc, aes-cfb,
	encryptedContent  []byte
	initialize_vector []byte
	masterKeySalt     []byte

	// buffer read from i/o file descriptor
	readBuffer []byte
}

const debug bool = false

// read the conf file for the input.yaml to the encrypt tool
func (conf *EncryptUtilInputArgs) readConfFile(fileName string) *EncryptUtilInputArgs {
	inputFile, err := os.ReadFile("input.yaml")
	if err != nil {
		panic("Error the Encrypt tool requires the yaml config file Please create a [input.yaml file]")
	}

	err = yaml.Unmarshal(inputFile, conf)
	if err != nil {
		panic("The required input.yaml file is corrupted")
	}

	return conf
}

// since it uses pbkdf2 with a fixed length for different hashing algoritgh
// matching the collusiona and hash strength of underlying hashing alg, the keySize should match the size of underlying
// symmetric encryption algorithm
// from NIST guidelenes irrespective of hashing algorithm its secure to keep the salt size 16 bytes
// if i create size same as the encryption key the has strength is n / 2 but better to keep it twice the size and truncate in half
// this ensures stronger hash strength equals the length (stronger collusion resistance) of key but require the key to be truncated into half
func (enc *EncryptUtil) getKeySize() int {
	switch enc.inputArgs.Symmetric_encryption_algorithm {
	case "des3-3k-cbc", "des3-3k-cfb":
		return (192 / (1 << 3)) * 2 // (24 bytes (internal 3 keys of 8 bytes each))
	case "aes-128-cbc", "aes-128-cfb", "aes-128-gcm":
		return ((1 << 7) / (1 << 3)) * 2 // (16 bytes key) * 2 [to ensure i get whole collusion resistance strength]
	case "aes-256-cbc", "aes-256-cfb", "aes-256-gcm":
		return ((1 << 8) / (1 << 3)) * 2 // (32 bytes key) * 2 [to ensure i get whole collusion resistance strength]
	default:
		panic("Error the algorithm is not supported by Enc Util")
	}
}

/*
Experimental method I wrote to learn and explore more with argon (Argon2i) based
time=3, and memory=32*1024
Number of threads: Number of avaialaible CPU cores
*/
func (enc *EncryptUtil) generateArgonMasterHash() {
	salt := enc.genRandBytes(aes.BlockSize)
	password := utils.GetComplexPassword("encrypt")
	cpuCount := runtime.NumCPU()

	keySize := enc.getKeySize()
	masterKey := argon2.Key([]byte(password), salt, 3, 32*(1<<10), uint8(cpuCount), uint32(keySize))

	enc.master_key = masterKey[:len(masterKey)/2]
	enc.masterKeySalt = salt
	if debug {
		fmt.Println("salt is ::")
		utils.DebugEncodedKey(salt)
		utils.DebugEncodedKey(enc.master_key)
	}
}

/*
Experimental method I wrote to learn and explore more with argon (Argon2i) based mem
time=3, and memory=32*1024
Number of threads: Number of avaialaible CPU cores
*/
func (enc *EncryptUtil) generateArgonEncHmacHashes() {
	saltString_enc := utils.SaltString_enc
	saltString_hmac := utils.SaltString_hmac

	var hmac_key []byte
	var enc_key []byte
	cpuCount := runtime.NumCPU()

	keySize := enc.getKeySize()
	hmac_key = argon2.Key(enc.master_key,
		saltString_hmac, 3, 3*(1<<10), uint8(cpuCount), uint32(keySize))
	enc_key = argon2.Key(enc.master_key,
		saltString_enc, 3, 3*(1<<10), uint8(cpuCount), uint32(keySize))

	enc.hmac_key = hmac_key[:len(hmac_key)/2]
	enc.encryption_key = enc_key[:len(enc_key)/2]

	if debug {
		fmt.Println("Hmac key")
		utils.DebugEncodedKey(enc.hmac_key)
		utils.DebugEncodedKey(enc.encryption_key)
	}
}

// derive the master key using pbkdf2 based the keysize found for underlying symmetric encryption alg
func (enc *EncryptUtil) generateMasterKey() {
	salt := enc.genRandBytes(aes.BlockSize) // keeping this same as aes block size considering the stength to be of (1 << 16)  bits
	password := utils.GetComplexPassword("encrypt")

	var masterKey []byte
	keyLength := enc.getKeySize()
	fmt.Printf("Key Size Used for Algorithm :: %s size :: %d bytes \n", enc.inputArgs.Symmetric_encryption_algorithm, keyLength)

	switch enc.inputArgs.Hashing_algorithm {
	case "sha256":
		masterKey = pbkdf2.Key([]byte(password), salt, int(enc.inputArgs.Pbkdf2_iteration_count),
			keyLength, sha3.New256)
		fmt.Println("Using Sha3 :: Using sha3-", enc.inputArgs.Hashing_algorithm)
	case "sha512":
		masterKey = pbkdf2.Key([]byte(password), salt, int(enc.inputArgs.Pbkdf2_iteration_count),
			keyLength, sha3.New512)
		fmt.Println("Using Sha3 :: Using ", enc.inputArgs.Hashing_algorithm)
	default:
		fmt.Errorf("Algorithm Not supported")
	}
	if debug {
		fmt.Println("Salt ::")
		utils.DebugEncodedKey(salt)
		utils.DebugEncodedKey(masterKey)
	}
	enc.master_key = masterKey[:len(masterKey)/2]
	enc.masterKeySalt = salt
}

// derive the hmac and encryption key from the master key
// the hmac and encryption key use a fixed salt
func (enc *EncryptUtil) deriveHmacEncKeys() {
	saltString_enc := utils.SaltString_enc
	saltString_hmac := utils.SaltString_hmac
	var hmac_key []byte
	var enc_key []byte
	keySize := enc.getKeySize()
	switch enc.inputArgs.Hashing_algorithm {
	case "sha256":
		hmac_key = pbkdf2.Key(enc.master_key, saltString_hmac, 1, keySize, sha3.New256)
		enc_key = pbkdf2.Key(enc.master_key, saltString_enc, 1, keySize, sha3.New256)
	case "sha512":
		hmac_key = pbkdf2.Key(enc.master_key, saltString_hmac, 1, keySize, sha3.New512)
		enc_key = pbkdf2.Key(enc.master_key, saltString_enc, 1, keySize, sha3.New512)
	default:
		fmt.Errorf("Algorithm Not Supported")
	}
	if debug {
		utils.DebugEncodedKey(hmac_key)
		utils.DebugEncodedKey(enc_key)
	}
	enc.hmac_key = hmac_key[:len(hmac_key)/2]
	enc.encryption_key = enc_key[:len(enc_key)/2]
}

// Used the crypto rand as agains math/rand which uses psuedo random number causing more collusion in the generated random output
func (enc *EncryptUtil) genRandBytes(bytelength int) []byte {
	randBytes := make([]byte, bytelength)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("error in generating crypto secured rand")
	}
	return randBytes
}

// read the file to be encrypted
// read the entire file using readall from the open file descriptor as against reading line by line
func (enc *EncryptUtil) readFileBufffer(fileName string) {
	var readBuffer []byte
	file, err := os.Open(fileName)

	if err != nil {
		panic(err)
	}

	readBuffer, err_file := io.ReadAll(file)
	if err_file != nil {
		panic("Error in readding to file buffer")
	}

	defer file.Close()

	enc.readBuffer = readBuffer
}

// des will use pkcs5 padding and only maling it work first des for cbc mode
func (enc *EncryptUtil) desEncrypt() {
	input_file_name := enc.inputArgs.Plain_text_file_name

	enc.readFileBufffer(input_file_name)

	// init the block size for the 3DES (DES done 3 times) (8 bytes)
	block, err := des.NewTripleDESCipher(enc.encryption_key)

	if err != nil {
		panic(err.Error())
		// panic("the keys size is incrrect for 3des ")
	}

	/*
		GCM (Galois/Counter Mode) is an encryption mode that combines the Counter Mode (CTR) of encryption with polynomial hashing.
			 GCM mode only works with 128 bits blocks that AES uses
			 DES wont work with GCM because the block size is 8 bytes or 64 bits
	*/
	if strings.Contains(enc.inputArgs.Symmetric_encryption_algorithm, "cfb") {
		var iv []byte = enc.genRandBytes(des.BlockSize)
		mode := cipher.NewCFBEncrypter(block, iv)
		ciphertext := make([]byte, len(enc.readBuffer))

		// run cfb mode (stream cipher conversion internally for cbc ) and write the output in ciphertext
		// this mode does not requre padding referred from rfc
		mode.XORKeyStream(ciphertext, enc.readBuffer)
		if debug && len(ciphertext) < (1<<8) {
			fmt.Println("DES: CFB Mode")
			utils.DebugEncodedKey(ciphertext)
		}

		enc.initialize_vector = iv
		enc.encryptedContent = ciphertext
	} else if strings.Contains(enc.inputArgs.Symmetric_encryption_algorithm, "cbc") {
		// des follows pkcs5 based padding support
		// the method i wrote for padding is adaptable for both pkcs5 and okcs7 since it consider
		// cipher block size while performing any padding
		sample_plain_raw_padding := PKCSPadding([]byte(enc.readBuffer), block)
		iv := enc.genRandBytes(des.BlockSize)

		// init the mode
		cipher_encryptor := cipher.NewCBCEncrypter(block, iv)

		ciphertext := make([]byte, len(sample_plain_raw_padding))

		// run the cbc mode over the raw text and dump the output in the ciphertext
		cipher_encryptor.CryptBlocks(ciphertext, sample_plain_raw_padding)

		if debug && len(ciphertext) < (1<<8) {
			utils.DebugEncodedKey(ciphertext)
		}
		enc.initialize_vector = iv
		enc.encryptedContent = ciphertext
	}

}

// padding support to implement padding
// this method is adaptable to support both pkcs5  and phekcs7
// it is determined based on the block size for the cipher
func PKCSPadding(ciphertext []byte, block cipher.Block) []byte {
	if len(ciphertext)%block.BlockSize() == 0 {
		return ciphertext
	}
	// no. of padding bytes which are required
	padding := block.BlockSize() - len(ciphertext)%block.BlockSize()

	// Create a byte slice with the padding value repeated 'padding' times
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...) // append this to the ciphertext
}

// this can also cover aes different block chaining modes
func (enc *EncryptUtil) aesEncrypt() {

	input_file_name := enc.inputArgs.Plain_text_file_name

	enc.readFileBufffer(input_file_name)

	// go main crypto uses pkcs7 padding for aes all modes
	if debug {
		fmt.Println("aes block size is ", aes.BlockSize)
	}

	block, err := aes.NewCipher(enc.encryption_key)
	if err != nil {
		panic(err)
	}

	/*
		The function dont really care about different input keys size for different aes variants
		The Key size will be passed accordingly based on the algorithm type
		the main goal is to provide different block chaining modes abstracting key size checking for this function
	*/
	if strings.Contains(enc.inputArgs.Symmetric_encryption_algorithm, "gcm") {
		aesGcm, err := cipher.NewGCM(block)
		nonce := enc.genRandBytes(aesGcm.NonceSize())

		if err != nil {
			panic(err.Error())
		}

		// additional data, nonce, readBuffer, nill
		// Seal encrypts and authenticates plaintext, authenticates the
		// additional data and appends the result to dst, returning the updated
		// slice. The nonce for the  NonceSize() bytes long and unique for all for a key
		// to prevent any leakage of the plaintext using crypto rand same as iv for generating nonce
		cipherText := aesGcm.Seal(nil, nonce, enc.readBuffer, nil)

		if debug && len(cipherText) < (1<<8) {
			fmt.Println("AES: GCM Mode")
			utils.DebugEncodedKey(cipherText)
		}

		enc.initialize_vector = nonce // treat nonce as IV for the GCM
		enc.encryptedContent = cipherText
	} else if strings.Contains(enc.inputArgs.Symmetric_encryption_algorithm, "cfb") {
		var iv []byte = enc.genRandBytes(aes.BlockSize)
		mode := cipher.NewCFBEncrypter(block, iv)
		ciphertext := make([]byte, len(enc.readBuffer))

		mode.XORKeyStream(ciphertext, enc.readBuffer)

		if debug && len(ciphertext) < (1<<8) {
			fmt.Println("AES: CFB Mode")
			utils.DebugEncodedKey(ciphertext)
		}

		enc.initialize_vector = iv
		enc.encryptedContent = ciphertext

	} else if strings.Contains(enc.inputArgs.Symmetric_encryption_algorithm, "cbc") {
		var iv []byte = enc.genRandBytes(aes.BlockSize)
		cbc := cipher.NewCBCEncrypter(block, iv)
		var sample_plain_padding []byte
		sample_plain_padding = PKCSPadding(enc.readBuffer, block)

		// fmt.Println("The padded text is ", sample_plain_padding)
		// the input to the aes is done via (iv size) + (len(pkcs7 padded plain text the block aes cipher in CBC mode))
		ciphertext := make([]byte, len(sample_plain_padding))

		cbc.CryptBlocks(ciphertext, sample_plain_padding)

		if debug && len(ciphertext) < (1<<8) {
			fmt.Println("AES: CBC Mode")
			utils.DebugEncodedKey(ciphertext)
		}

		// store the message storage block
		enc.initialize_vector = iv
		enc.encryptedContent = ciphertext
	}
}

// function to generate the hmac integrity code over the encrypted content
func (enc *EncryptUtil) generateHmacOverEncryption() {

	var hmac_hash hash.Hash
	switch enc.inputArgs.Hashing_algorithm {
	case "sha256":
		hmac_hash = hmac.New(sha3.New256, enc.hmac_key)
	case "sha512":
		hmac_hash = hmac.New(sha3.New512, enc.hmac_key)
	default:
		fmt.Errorf("Algorithm not supported")
		panic("Error the algorithm for key sign not supported")
	}

	// the hmac should be generated over the IV + Encrypted content
	message_integrity_content := append(enc.initialize_vector, enc.encryptedContent...)

	hmac_hash.Write(message_integrity_content)

	// no need to append some extra padding of bytes over the hmac integrity code hash
	message_integrity_mac := hmac_hash.Sum(nil)
	enc.hmac_integrity_code = message_integrity_mac

	if debug {
		fmt.Println("Hmac code is : Hashed using ", enc.inputArgs.Hashing_algorithm)
		utils.DebugEncodedKey(message_integrity_mac)
	}
}

// function util to write the output in the bianry format
// the structure of the bianry is
// during ecnrypption first encrypt and tehm mac
//
//	Metadata + HMAC (iV + Cipher_text) + Cipher_Text (Payload)
//
// The binary format is go serialized binary or GOB
func (enc *EncryptUtil) writeEncyptedtoBinary(ciphertext []byte) {
	handler := func() {
		file, err := os.Create(enc.inputArgs.Encrypted_file_output_name)
		if err != nil {
			panic(err)
		}

		defer file.Close()

		// metadata {hashing_alg, encypt_alg, iteration_count, master_salt, encrypt_util_version} + hmac + + ciphertext

		header := utils.Metadata{
			Hashing_algorithm:              enc.inputArgs.Hashing_algorithm,
			Symmetric_encryption_algorithm: enc.inputArgs.Symmetric_encryption_algorithm,
			Pbkdf2_iteration_count:         enc.inputArgs.Pbkdf2_iteration_count,
			Encrypt_util_version:           enc.inputArgs.Version,
			Hashing_Salt:                   enc.masterKeySalt,
			Encrypt_IV:                     enc.initialize_vector,
			Argon_Hash_Mode:                enc.inputArgs.Argon_Hash_Mode,
		}

		binaryStruct := utils.BinaryStruct{
			Metadata:   header,
			Hmac:       enc.hmac_integrity_code,
			Ciphertext: enc.encryptedContent,
		}

		binaryStruct.MetadataSize = binary.Size(binaryStruct.Metadata)
		binaryStruct.CiphertextSize = binary.Size(binaryStruct.Ciphertext)
		binaryStruct.HmacSize = binary.Size(binaryStruct.Hmac)

		encoder := gob.NewEncoder(file)

		err = encoder.Encode(binaryStruct)
		// I built and compiled the code on m2 arm which follows BigEndian for binary order consider arm cpu architecture

		if err != nil {
			panic(err.Error())
		}

	}

	if _, err := os.Stat(enc.inputArgs.Encrypted_file_output_name); err == nil {
		os.Remove(enc.inputArgs.Encrypted_file_output_name)
		handler()
	} else if errors.Is(err, os.ErrNotExist) {
		handler()
	} else if errors.Is(err, os.ErrPermission) {
		fmt.Errorf("Panic: File Permission changed use chown -$ filename")
		panic("error file Permission Issue")
	}
}

func (enc *EncryptUtil) debugInputParamsMetadata(inputArgs *EncryptUtilInputArgs) {
	fmt.Println("--- Util Version --- ", inputArgs.Version)
	fmt.Println("--- Hashing Algorithm --- ", inputArgs.Hashing_algorithm)
	fmt.Println("--- Encryption Algorithm --- ", inputArgs.Symmetric_encryption_algorithm)
	fmt.Println("--- KDF Interation Count  --- ", inputArgs.Pbkdf2_iteration_count)
	fmt.Println("--- Encrypted Output File Name  --- ", inputArgs.Encrypted_file_output_name)
	fmt.Println("--- using Argon Mode for KDF ---", inputArgs.Argon_Hash_Mode)
}

// main driver to run the encryption util over the payload
func main() {
	var encrypt_util *EncryptUtil = &EncryptUtil{}
	var encrypt_util_input *EncryptUtilInputArgs = &EncryptUtilInputArgs{}

	fmt.Println("//////// Encryption Tool Started //////// ")
	fileName := utils.GetInputFileName("encrypt")

	encrypt_util_input = encrypt_util_input.readConfFile(fileName)
	encrypt_util.debugInputParamsMetadata(encrypt_util_input)
	encrypt_util.inputArgs = encrypt_util_input
	encrypt_util.inputArgs.Plain_text_file_name = fileName

	if !encrypt_util.inputArgs.Argon_Hash_Mode {
		encrypt_util.generateMasterKey()
		encrypt_util.deriveHmacEncKeys()
	} else {
		encrypt_util.generateArgonMasterHash()
		encrypt_util.generateArgonEncHmacHashes()
	}

	if strings.HasPrefix(encrypt_util.inputArgs.Symmetric_encryption_algorithm, "aes") {
		encrypt_util.aesEncrypt()
	} else {
		encrypt_util.desEncrypt()
	}

	encrypt_util.generateHmacOverEncryption()
	encrypt_util.writeEncyptedtoBinary(encrypt_util.encryptedContent)
	fmt.Printf("\n ////////  Encryption Completed Encrypted file stored in %s /////", encrypt_util_input.Encrypted_file_output_name)
}
