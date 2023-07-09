package crypto

import (
	"crypto/rsa"
	"github.com/ProtonMail/go-crypto/openpgp/ed25519"
	"github.com/ProtonMail/go-crypto/openpgp/x25519"
	"io/ioutil"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testTime = 1557754627 // 2019-05-13T13:37:07+00:00

func readTestFile(name string, trimNewlines bool) string {
	data, err := ioutil.ReadFile("testdata/" + name) //nolint
	if err != nil {
		panic(err)
	}
	if trimNewlines {
		return strings.TrimRight(string(data), "\n")
	}
	return string(data)
}

func init() {
	UpdateTime(testTime) // 2019-05-13T13:37:07+00:00

	initGenerateKeys()
	initArmoredKeys()
	initKeyRings()
}

func assertBigIntCleared(t *testing.T, x *big.Int) {
	w := x.Bits()
	for k := range w {
		assert.Exactly(t, big.Word(0x00), w[k])
	}
}

func assertMemCleared(t *testing.T, b []byte) {
	for k := range b {
		assert.Exactly(t, uint8(0x00), b[k])
	}
}

func assertRSACleared(t *testing.T, rsaPriv *rsa.PrivateKey) {
	assertBigIntCleared(t, rsaPriv.D)
	for idx := range rsaPriv.Primes {
		assertBigIntCleared(t, rsaPriv.Primes[idx])
	}
	assertBigIntCleared(t, rsaPriv.Precomputed.Qinv)
	assertBigIntCleared(t, rsaPriv.Precomputed.Dp)
	assertBigIntCleared(t, rsaPriv.Precomputed.Dq)

	for idx := range rsaPriv.Precomputed.CRTValues {
		assertBigIntCleared(t, rsaPriv.Precomputed.CRTValues[idx].Exp)
		assertBigIntCleared(t, rsaPriv.Precomputed.CRTValues[idx].Coeff)
		assertBigIntCleared(t, rsaPriv.Precomputed.CRTValues[idx].R)
	}
}

func assertEd25519Cleared(t *testing.T, priv *ed25519.PrivateKey) {
	assertMemCleared(t, priv.Key)
}

func assertX25519Cleared(t *testing.T, priv *x25519.PrivateKey) {
	assertMemCleared(t, priv.Secret)
}
