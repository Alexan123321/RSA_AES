package aesexample

import (
	"bytes"
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

	/* Allocate memory for the ciphertext and the block */
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	/* Apply CTR operation with the AES cipher and the block */
	ctr := cipher.NewCTR(c, iv)

	/* Encrypt the text and store it in the ciphertext */
	ctr.XORKeyStream(ciphertext[aes.BlockSize:], text)

	/* Finally, the text is encrypted, and the text is written to the file */
	err = ioutil.WriteFile(filename+".data", ciphertext, 0777)
	if err != nil {
		fmt.Println(err)
	}
	return
}

/* Decrypt method */
func DecryptFromFile(inputKey, filename string) []byte {
	/* Read ciphertext from file */
	ciphertext, err := ioutil.ReadFile(filename + ".data")
	if err != nil {
		fmt.Println(err)
	}

	/* Allocate block */
	iv := ciphertext[:aes.BlockSize]

	/* Create AES cipher from the key provided */
	c, err := aes.NewCipher([]byte(inputKey))
	if err != nil {
		fmt.Println(err)
	}

	/* Apply CTR operation with the AES cipher */
	ctr := cipher.NewCTR(c, iv)
	if err != nil {
		fmt.Println(err)
	}

	/* Allocate memory for the plaintext */
	plaintext := make([]byte, len(ciphertext))

	/* Decrypt the ciphertext using the same procedure as for encryption */ //NOTE: only viable as it is CTR
	ctr.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	/* Trim the decrypted plaintext to remove nil bytes */
	plaintext = bytes.Trim(plaintext, "\x00")
	return plaintext
}
