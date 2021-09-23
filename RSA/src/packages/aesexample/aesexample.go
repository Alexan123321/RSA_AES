package aesexample

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
)

/* EncryptToFile method */
func EncryptToFile(inputText, inputKey, filename string) {
	/* Cast text and key to bytes */
	text := []byte(inputText)
	key := []byte(inputKey)

	/* Create AES cipher from the key provided */
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	/* Apply Galois Counter Mode operation with the AES cipher */
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	/* Make a byte array of the size of the nonce of GCM */
	nonce := make([]byte, gcm.NonceSize())

	/* Fill the nonce with random data */
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		fmt.Println(err)
	}

	/* Finally, the text is encrypted, and the text is written to the file */
	err = ioutil.WriteFile(filename+".data", gcm.Seal(nonce, nonce, text, nil), 0777)
	if err != nil {
		fmt.Println(err)
	}
	return
}

/* Decrypt method */
func DecryptToFile(inputKey, filename string) []byte {
	/* Read ciphertext from file */
	ciphertext, err := ioutil.ReadFile(filename + ".data")
	if err != nil {
		fmt.Println(err)
	}

	/* Create AES cipher from the key provided */
	c, err := aes.NewCipher([]byte(inputKey))
	if err != nil {
		fmt.Println(err)
	}

	/* Apply Galois Counter Mode operation with the AES cipher */
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	/* Compare size of nonce to size of GCM nonce */
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	/* Decrypt ciphertext and store as plaintext */
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return plaintext
}
