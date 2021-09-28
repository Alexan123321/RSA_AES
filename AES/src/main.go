package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"week_4/src/packages/aesexample"
	"week_4/src/packages/rsaexample"
)

func main() {
	if test() == true {
		fmt.Println("Success!")
	} else {
		fmt.Println("Try again, Alex...")
	}
	return
}

/* Test method */
func test() bool {
	/* Initialize constants */
	filename := "SuperSecretKey"
	key := "SoWeBeatOnBoatsAgainstTheCurrent" //NOTE: Needs to be 32 bits
	e := 3

	/* Generate pseudo-random k */
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	k, err := rand.Int(rand.Reader, max)
	if err != nil {
		fmt.Println(err)
	}

	/* Generate public and private key */
	publicKey, privateKey := rsaexample.KeyGen(k, e)

	/* Serialize the privat key */
	jsonString, _ := json.Marshal(privateKey)

	/* Encrypt the serialized private key to a file */
	aesexample.EncryptToFile(string(jsonString), key, filename)

	/* Decrypt the serialized private key from the file */
	decryptedJsonString := aesexample.DecryptFromFile(key, filename)

	/* Deserialize the private key */
	decryptedPrivateKey := rsaexample.Key{}
	json.Unmarshal(decryptedJsonString, &decryptedPrivateKey)

	/* Generate random message */
	m, err := rand.Int(rand.Reader, publicKey.N)
	if err != nil {
		fmt.Println(err)
	}

	/* Encrypt a message using RSA */
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

/**
* // Sender:
* 1) Hash the message using SHA-256
* 2) Apply one-time pad to the message itself (XOR cipher?)
* 3) Hash value is signed by appending a RSA encrypted address (using the private key of the sender)
*
* // From:
* 1) Sender applies the public key to verify the signature, i.e checks if the address matches the sender
* 2) Decrypts using one-time padding
* 3) Decrypts using SHA-256
**/

// https://www.cryptomuseum.com/manuf/mils/files/mils_otp_proof.pdf
