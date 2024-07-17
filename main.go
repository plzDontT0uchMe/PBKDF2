package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 16
	keySize    = 32
	iterations = 1000
)

func generateSalt() []byte {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}
	return salt
}

func createHash(password string) string {
	salt := generateSalt()
	hash := pbkdf2.Key([]byte(password), salt, iterations, keySize, sha1.New)
	hashedPassword := append([]byte{0}, append(salt, hash...)...)
	return base64.StdEncoding.EncodeToString(hashedPassword)
}

func checkPassword(password, hashedPassword string) bool {
	hashedPasswordBytes, _ := base64.StdEncoding.DecodeString(hashedPassword)
	saltBytes := hashedPasswordBytes[1 : saltSize+1]
	passwordBytes := hashedPasswordBytes[saltSize+1:]
	newPasswordBytes := pbkdf2.Key([]byte(password), saltBytes, iterations, keySize, sha1.New)
	for i := 0; i < len(passwordBytes); i++ {
		if newPasswordBytes[i] != passwordBytes[i] {
			return false
		}
	}
	return true
}

func main() {
	password := "123"
	hashedPasswordWithSalt := createHash(password)
	if checkPassword(password, hashedPasswordWithSalt) {
		fmt.Println("Password is valid")
	} else {
		fmt.Println("Password is not valid")
	}
	if checkPassword("321", hashedPasswordWithSalt) {
		fmt.Println("Password is valid")
	} else {
		fmt.Println("Password is not valid")
	}
	if checkPassword("122", hashedPasswordWithSalt) {
		fmt.Println("Password is valid")
	} else {
		fmt.Println("Password is not valid")
	}
	if checkPassword("123.", hashedPasswordWithSalt) {
		fmt.Println("Password is valid")
	} else {
		fmt.Println("Password is not valid")
	}
	if checkPassword(password, "ACv82CQNvPKK3Q0vw3hqrlC58d1b5QXA8PLe7KpMHZAZhXHHiVUPyZc6PjaxghO9/Q==") {
		fmt.Println("Password is valid")
	} else {
		fmt.Println("Password is not valid")
	}
	if checkPassword(password, "AJWEn7hkwU6R2v1iFNAbZZ87RtxKsBPf8aRDhzKruLv6M84W29ulwdcckUhUFpiQJA==") {
		fmt.Println("Password is valid")
	} else {
		fmt.Println("Password is not valid")
	}
	if checkPassword(password, "AJWEn7hkwU6R2v1iFNAbZZ87RtxKsBPf7aRDhzKruLv6M84W29ulwdcckUhUFpiQJA==") {
		fmt.Println("Password is valid")
	} else {
		fmt.Println("Password is not valid")
	}
}
