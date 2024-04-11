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

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v2"
	"synarcs.com/css577/utils"
)

type EncryptUtilInputArgs struct {
	Version int `yaml:"version"`

	// algorithm information
	Hashing_algorithm              string `yaml:"hashing_algorithm"`
	Symmetric_encryption_algorithm string `yaml:"symmetric_encryption_algorithm"`

	// iteration count for kdf using custom random secured rand salt
	Pbkdf2_iteration_count     int    `yaml:"pbkdf2_iteration_count"`
	Plain_text_file_name       string `yaml:"plain_text_file_name"`
	Encrypted_file_output_name string `yaml:"encrypted_file_output_name"`
}

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
	iv                []byte
	masterKeySalt     []byte

	// plain text conten
	readBuffer []byte
}

const debug bool = false

// read the conf file for the input.yaml to the encrypt tool
func (conf *EncryptUtilInputArgs) readConfFile() *EncryptUtilInputArgs {
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

func (enc *EncryptUtil) getKeyHashSize() int {
	switch enc.inputArgs.Symmetric_encryption_algorithm {
	case "des3-2k":
		return 56 * 2
	case "des3-3k":
		return 56 * 3
	case "aes-128-cbc":
		return (1 << 7) / (1 << 3) // aes key size (bits) / 1 byte size (pbkdf2 go requires key in bytes)
	case "aes-256-cbc":
		return (1 << 8) / (1 << 3)
	default:
		panic("Error the algorithm is not supported by Enc Util")
	}
}

func (enc *EncryptUtil) generateMasterKey() {
	salt := enc.genRandBytes(aes.BlockSize) // keeping this same as aes block size considering the stength to be of (1 << 16)  bits
	password := utils.GetComplexPassword()
	fmt.Println("Salt ::")
	utils.DebugEncodedKey(salt)
	var masterKey []byte
	keyLength := enc.getKeyHashSize()
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
	utils.DebugEncodedKey(masterKey)
	enc.master_key = masterKey
	enc.masterKeySalt = salt
}

func (enc *EncryptUtil) deriveHmacEncKeys() {
	saltString_enc := []byte("encrption_fixed_str")
	saltString_hmac := []byte("hmac_fixed_str")
	var hmac_key []byte
	var enc_key []byte
	switch enc.inputArgs.Hashing_algorithm {
	case "sha256":
		hmac_key = pbkdf2.Key(enc.master_key, saltString_hmac, 1, len(enc.master_key), sha3.New256)
		enc_key = pbkdf2.Key(enc.master_key, saltString_enc, 1, len(enc.master_key), sha3.New256)
	case "sha512":
		hmac_key = pbkdf2.Key(enc.master_key, saltString_hmac, 1, len(enc.master_key), sha3.New512)
		enc_key = pbkdf2.Key(enc.master_key, saltString_enc, 1, len(enc.master_key), sha3.New512)
	default:
		fmt.Errorf("Algorithm Not Supported")
	}
	utils.DebugEncodedKey(hmac_key)
	utils.DebugEncodedKey(enc_key)
	enc.hmac_key = hmac_key
	enc.encryption_key = enc_key
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

func (enc *EncryptUtil) readFileAndEncryptFlush(fileName string) {
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
// TODO: Also adding support for other modes later
func (enc *EncryptUtil) desEncrypt() ([]byte, error) {
	input_file_name := enc.inputArgs.Plain_text_file_name
	enc.readFileAndEncryptFlush(input_file_name)
	var sample_plain_raw string
	sample_plain_raw = string(enc.readBuffer)

	block, err := des.NewTripleDESCipher(enc.encryption_key)

	if err != nil {
		fmt.Println(err)
		// panic("the keys size is incrrect for 3des ")
	}

	sample_plain_raw_padding := PKCSPadding([]byte(sample_plain_raw), block)
	iv := enc.genRandBytes(des.BlockSize)

	cipher_encryptor := cipher.NewCBCEncrypter(block, iv)

	cipher_text := make([]byte, enc.getKeyHashSize())

	cipher_encryptor.CryptBlocks(cipher_text, sample_plain_raw_padding)

	return cipher_text, nil
}

func PKCSPadding(ciphertext []byte, block cipher.Block) []byte {
	if len(ciphertext)%block.BlockSize() == 0 {
		return ciphertext
	}
	padding := block.BlockSize() - len(ciphertext)%block.BlockSize()
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// this can also cover aes different block chaining modes
// TODO: Add support for different chaining mode in the same method
func (enc *EncryptUtil) aesEncrypt() {
	var iv []byte = enc.genRandBytes(aes.BlockSize)

	input_file_name := enc.inputArgs.Plain_text_file_name

	enc.readFileAndEncryptFlush(input_file_name)

	// go main crypto uses pkcs7 padding for aes all modes
	if debug {
		fmt.Println("aes block size is ", aes.BlockSize)
	}

	block, err := aes.NewCipher(enc.encryption_key)
	if err != nil {
		panic(err)
	}

	var sample_plain_padding []byte
	sample_plain_padding = PKCSPadding(enc.readBuffer, block)

	// fmt.Println("The padded text is ", sample_plain_padding)
	// the input to the aes is done via (iv size) + (len(pkcs7 padded plain text the block aes cipher in CBC mode))
	ciphertext := make([]byte, aes.BlockSize+len(sample_plain_padding))

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], sample_plain_padding)

	fmt.Println("AES: CBC Mode")
	utils.DebugEncodedKey(ciphertext)

	// store the message storage block
	enc.encryptedContent = ciphertext
}

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

	message_integrity_content := append(enc.iv, enc.encryptedContent...)

	hmac_hash.Write(message_integrity_content)

	message_integrity_mac := hmac_hash.Sum(nil)
	enc.hmac_integrity_code = message_integrity_mac

	fmt.Println("Hmac code is : Hashed using ", enc.inputArgs.Hashing_algorithm)
	utils.DebugEncodedKey(message_integrity_mac)
}

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
			Hashing_Salt: 					enc.masterKeySalt,
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
			panic(err)
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

func main() {
	var encrypt_util *EncryptUtil = &EncryptUtil{}
	var encrypt_util_input *EncryptUtilInputArgs = &EncryptUtilInputArgs{}

	encrypt_util_input = encrypt_util_input.readConfFile()
	fmt.Println(*encrypt_util_input)

	encrypt_util.inputArgs = encrypt_util_input
	encrypt_util.generateMasterKey()
	encrypt_util.deriveHmacEncKeys()

	encrypt_util.aesEncrypt()

	encrypt_util.generateHmacOverEncryption()
	encrypt_util.writeEncyptedtoBinary(encrypt_util.encryptedContent)
}
