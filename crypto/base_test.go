package crypto

import (
	"crypto/rsa"
	"io/ioutil"
	"math/big"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/gopenpgp/v3/profile"

	"github.com/stretchr/testify/assert"
)

const testTime = 1557754627 // 2019-05-13T13:37:07+00:00
const testMessage = "Hello world!"

var testPGP *PGPHandle
var testProfiles []*profile.Custom

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
	testPGP = PGP()
	testPGP.defaultTime = NewConstantClock(testTime) // 2019-05-13T13:37:07+00:00
	testPGP.localTime = NewConstantClock(testTime)   // 2019-05-13T13:37:07+00:00
	testProfiles = []*profile.Custom{profile.RFC4880(), profile.Koch(), profile.CryptoRefresh()}

	initEncDecTest()
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

func assertEdDSACleared(t *testing.T, priv *eddsa.PrivateKey) {
	assertMemCleared(t, priv.D)
}

func assertECDHCleared(t *testing.T, priv *ecdh.PrivateKey) {
	assertMemCleared(t, priv.D)
}
