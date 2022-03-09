package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func getFilePathAndFileName(filePath string) (string, string) {
	listParent := strings.Split(filePath, string(os.PathSeparator))
	return strings.Join(listParent[:len(listParent)-1], string(os.PathSeparator)), listParent[len(listParent)-1]
}

func removeFile(filePath string) {
	e := os.Remove(filePath)
	if e != nil {
		log.Println(e)
	}
}

func encryptFile(filePath string) (string, error) {
	plaintext, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	key, err := ioutil.ReadFile("key")
	if err != nil {
		log.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	// Save back to file
	DFilePath, DfileName := getFilePathAndFileName(filePath)
	DFilePath = DFilePath + string(os.PathSeparator) + "encrypt"
	err = os.MkdirAll(DFilePath, 0777)
	if err != nil {
		log.Println(err)
	}
	DFilePath = DFilePath + string(os.PathSeparator) + DfileName
	err = ioutil.WriteFile(DFilePath, ciphertext, 0777)
	if err != nil {
		log.Panic(err)
	}

	// defer removeFile(filePath)
	return DFilePath, nil
}

func decryptFile(filePath string) (string, error) {
	ciphertext, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	key, err := ioutil.ReadFile("key")
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Panic(err)
	}

	// Save back to file
	DFilePath, DfileName := getFilePathAndFileName(filePath)
	DFilePath = DFilePath + string(os.PathSeparator) + "decrypt"
	err = os.MkdirAll(DFilePath, 0777)
	if err != nil {
		log.Println(err)
	}
	DFilePath = DFilePath + string(os.PathSeparator) + DfileName
	err = ioutil.WriteFile(DFilePath, plaintext, 0777)
	if err != nil {
		log.Panic(err)
	}
	//defer removeFile(filePath)
	return DFilePath, nil
}

func main() {
	fmt.Println("Started Program")
	FilePath := "C:\\Users\\jdsouza\\OneDrive - Extreme Networks, Inc\\Documents\\GoWorkspace\\MyPrograms\\ENC_DEC\\plaintext_dec.txt"
	filePath_1, _ := encryptFile(FilePath)
	fmt.Printf("\t\tEncrypted at %v\n\n", filePath_1)

	filePath_2, _ := decryptFile(filePath_1)
	fmt.Printf("\t\tDecrypted at %v\n\n", filePath_2)

	fmt.Println("Ended Program")

}
