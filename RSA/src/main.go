/**
BY: Deyana Atanasova, Henrik Tambo Buhl & Alexander Stæhr Johansen
DATE: 22-09-2021 (Updated 28-09-2021)
COURSE: Distributed Systems and Security
DESCRIPTION: RSA en- and decryption template implementation.
**/

/**
The implementation is based on the book "Secure Distributed Systems" 2021,
section 5.2.1 by Ivan Damgaard, Jesper Buus Nielsen & Claudio Orlandi.
**/

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"week_4/src/packages/rsaexample"
)

func main() {
	/* Generate pseudo-random k */
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	k, err := rand.Int(rand.Reader, max)
	if err != nil {
		fmt.Println(err)
	}

	e := 3 //CHANGE ME

	/* Generate public and private key, respectively */
	publicKey, privateKey := rsaexample.KeyGen(k, e)

	/* Generate random message */
	m, err := rand.Int(rand.Reader, publicKey.N)
	if err != nil {
		fmt.Println(err)
	}

	/* Encrypt m with the public key */
	c := rsaexample.Encrypt(m, publicKey)

	/* Decrypt ciphertext with private key */
	decrypted := rsaexample.Decrypt(c, privateKey)

	/* Print message before encryption and after decryption */
	fmt.Println("Message before encryption: " + m.String())
	fmt.Println("Message after decryption: " + decrypted)
}
