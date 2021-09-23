/**
BY: Deyana Atanasova, Henrik Tambo Buhl & Alexander Stæhr Johansen
DATE: 22-09-2021
COURSE: Distributed Systems and Security
DESCRIPTION: RSA en- and decryption template implementation.
**/

/**
The implementation is based on the book "Secure Distributed Systems" 2021,
section 5.2.1 by Ivan Damgaard, Jesper Buus Nielsen & Claudio Orlandi.
**/

package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"
	"week_4/src/packages/rsaexample"
)

func main() {
	/* Generate random k */
	rand.Seed(time.Now().UnixNano())
	k := rand.Int()

	e := 3 //CHANGE ME

	/* Generate public and private key, respectively */
	publicKey, privateKey := rsaexample.KeyGen(k, e)

	m := 69 //CHANGE ME

	/* Encrypt m with the public key */
	c := rsaexample.Encrypt(m, publicKey)

	/* Decrypt ciphertext with private key */
	decrypted := rsaexample.Decrypt(c, privateKey)

	/* Print message before encryption and after decryption */
	fmt.Println("Message before encryption: " + strconv.Itoa(m))
	fmt.Println("Message after decryption: " + decrypted)
}
