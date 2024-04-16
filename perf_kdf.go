package main

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"synarcs.com/css577/utils"
)

const debug_perf bool = false

func generateKdfHash(iterCount int, password string, alg string) {

	salt := make([]byte, (1 << 4))
	_, err := rand.Read(salt)
	if err != nil {
		panic(err.Error())
	}
	var genHash []byte

	switch alg {
	case "sha256":
		genHash = pbkdf2.Key([]byte(password), salt, iterCount,
			(1 << 8), sha3.New256)
	case "sha512":
		genHash = pbkdf2.Key([]byte(password), salt, iterCount,
			(1 << 9), sha3.New512)
	default:
		fmt.Errorf("Algorithm Not supported")
	}
	if debug_perf {
		fmt.Println(genHash)
	}
}

func generateArgonHash(iterCount int, password string) {
	salt := make([]byte, (1 << 4))
	_, err := rand.Read(salt)
	if err != nil {
		panic(err.Error())
	}
	var genHash []byte
	cpuCount := runtime.NumCPU()
	genHash = argon2.Key([]byte(password), salt, 3, 512*(1<<10), uint8(cpuCount), uint32(iterCount))
	if debug_perf {
		fmt.Println(genHash)
	}
}

func main() {
	// dont count the time for i/o
	password := utils.GetComplexPassword("encrypt")

	startTime := time.Now().UnixMicro()
	for i := 0; (1 << i) < (1 << 16); i++ {
		generateKdfHash((1 << i), password, "sha256")

		endTIme := time.Now().UnixMicro()
		fmt.Printf("KDF HASH time took for HASH Alg SHA256 with keySize %d and iteration Count %d is :: %d micro seconds\n", (1 << 8), (1 << i), (endTIme - startTime))
	}

	startTime = time.Now().UnixMicro()
	for i := 0; (1 << i) < (1 << 16); i++ {
		generateKdfHash((1 << i), password, "sha512")

		endTIme := time.Now().UnixMicro()
		fmt.Printf("KDF HASH time took for HASH Alg SHA512 with keySize %d and iteration Count %d is :: %d micro seconds\n", (1 << 9), (1 << i), (endTIme - startTime))
	}

	startTime = time.Now().UnixMicro()
	generateArgonHash((1 << 8), password)

	endTIme := time.Now().UnixMicro()
	fmt.Printf("Argon KDF HASH time took with keySize %d and iteration Count %d is :: %d micro seconds\n", (1 << 9), (1 << 8), (endTIme - startTime))
}
