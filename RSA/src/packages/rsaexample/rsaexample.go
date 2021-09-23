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

package rsaexample

import (
	"crypto/rand"
	"math/big"
)

/* Key struct */
type Key struct {
	N      *big.Int
	E_or_d *big.Int
}

/* Key generator method */
func KeyGen(k int, e int) (Key, Key) {
	/* Convert constants 1, E and K to big ints */
	ONE := big.NewInt(1)
	E := big.NewInt(int64(e))
	K := big.NewInt(int64(k))

	/* Determine bitlength of k */
	bitLength := K.BitLen()

	/* Step 1: Generate prime, p, with half the bitlength of k.
	   - The reason is that the product of two numbers with bitlength n/2 is n */
	p, _ := rand.Prime(rand.Reader, bitLength/2)

	/* Step 2: Subtract 1 from p */
	P := new(big.Int).Sub(p, ONE)

	/* Step 3: Find GCD between E and P */
	gcd_1 := new(big.Int).GCD(nil, nil, E, P)

	/* For GCD != 1, repeat steps 1, 2 and 3 */
	for ONE.Cmp(gcd_1) != 0 {
		p, _ = rand.Prime(rand.Reader, bitLength/2)
		P = new(big.Int).Sub(p, ONE)
		gcd_1 = new(big.Int).GCD(nil, nil, E, P)
	}

	/* Generate prime q applying same procedure as explained for p */
	q, _ := rand.Prime(rand.Reader, bitLength/2)
	Q := new(big.Int).Sub(q, ONE)
	gcd_2 := new(big.Int).GCD(nil, nil, E, Q)
	for ONE.Cmp(gcd_2) != 0 && p.Cmp(q) != 0 {
		q, _ = rand.Prime(rand.Reader, bitLength/2)
		Q = new(big.Int).Sub(q, ONE)
		gcd_2 = new(big.Int).GCD(nil, nil, E, Q)
	}

	/* Generate public key as (n, e) */
	publicKey := Key{N: new(big.Int).Mul(p, q), E_or_d: E}

	/* Generate private key as (n, d) */
	privateKey := Key{N: new(big.Int).Mul(p, q), E_or_d: new(big.Int).ModInverse(E, new(big.Int).Mul(P, Q))}
	return publicKey, privateKey
}

/* Encrypt method */
func Encrypt(m int, publicKey Key) *big.Int {
	/* Cast m to big int */
	M := big.NewInt(int64(m))
	/* Generate ciphertext using the public key*/
	c := new(big.Int).Exp(M, publicKey.E_or_d, publicKey.N)
	return c
}

/* Decrypt method */
func Decrypt(c *big.Int, privateKey Key) string {
	/* Decrypt the message using the private key */
	m := new(big.Int).Exp(c, privateKey.E_or_d, privateKey.N)
	/* Cast m to string */
	M := m.String()
	return M
}
