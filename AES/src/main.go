package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
	"week_4/src/packages/aesexample"
	"week_4/src/packages/rsaexample"
)

func main() {
	if test() == true {
		fmt.Println("Success!")
	} else {
		fmt.Println("Try again, Alex...")
	}
}

/* Test method */
func test() bool {
	/* Initialize constants */
	filename := "SuperSecretKey"
	key := "SoWeBeatOnBoatsAgainstTheCurrent" //NOTE: Needs to be 32 bits
	e := 3

	/* Generate random k */
	rand.Seed(time.Now().UnixNano())
	k := rand.Int()

	/* Generate public and private key */
	publicKey, privateKey := rsaexample.KeyGen(k, e)

	/* Serialize the privat key */
	jsonString, _ := json.Marshal(privateKey)

	/* Encrypt the serialized private key to a file */
	aesexample.EncryptToFile(string(jsonString), key, filename)

	/* Decrypt the serialized private key from the file */
	decryptedJsonString := aesexample.DecryptToFile(key, filename)
	decryptedPrivateKey := rsaexample.Key{}

	/* Deserialize the private key */
	json.Unmarshal(decryptedJsonString, &decryptedPrivateKey)

	/* Encrypt a message using RSA */
	m := 69
	c := rsaexample.Encrypt(m, publicKey)

	/* Decrypt the message using the privateKey and decrypted private key
	and compare the returned strings */
	pureRSA := rsaexample.Decrypt(c, privateKey)
	RSAAES := rsaexample.Decrypt(c, decryptedPrivateKey)

	/* Print the descrypted strings for visual comparison */
	fmt.Println("PureRSA: " + pureRSA + "   RSA_AES: " + RSAAES)

	/* Return boolean comparison */
	return pureRSA == RSAAES
}
