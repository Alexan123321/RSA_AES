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

func GenerateRandomK() *big.Int {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	k, err := rand.Int(rand.Reader, max)
	if err != nil {
		fmt.Println(err)
	}
	return k
}

// TODO: get this to work - currently message before & encryption is different
func main() {
	/* Generate pseudo-random k (bit-length of the key)*/
	k := GenerateRandomK()
	e := 3

	/* Generate public and private key, respectively */
	publicKey, privateKey := rsaexample.KeyGen(k, e)

	/* Generate random message */
	m, _ := rand.Int(rand.Reader, publicKey.N)

	/* Generate RSA signature */
	s := rsaexample.GenerateSignature(m, publicKey)

	/* Verify RSA signature */
	isTheSame := rsaexample.VerifySignature(m.Bytes(), s, privateKey)
	println(isTheSame)
}
