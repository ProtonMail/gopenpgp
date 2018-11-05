package crypto

import (
	"bytes"
	"golang.org/x/crypto/openpgp/armor"
	"io/ioutil"
	"strings"
	"testing"
)

const testPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v0.7.1
Comment: http://openpgpjs.org

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
qqGRQm3MxoTdgQUShAwbNwNNQR9cInfMnA==
=2wIY
-----END PGP PRIVATE KEY BLOCK-----
`

const testPrivateKeyLegacy = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v0.9.0
Comment: http://openpgpjs.org

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
PPekG4ttm6z3/BqqVplanIRSXlsqyp6J8A==
=Pyb1
-----END PGP PRIVATE KEY BLOCK-----
`

const testPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v0.7.1
Comment: http://openpgpjs.org

xsBNBFRJbc0BCAC0mMLZPDBbtSCWvxwmOfXfJkE2+ssM3ux21LhD/bPiWefE
WSHlCjJ8PqPHy7snSiUuxuj3f9AvXPvg+mjGLBwu1/QsnSP24sl3qD2onl39
vPiLJXUqZs20ZRgnvX70gjkgEzMFBxINiy2MTIG+4RU8QA7y8KzWev0btqKi
MeVa+GLEHhgZ2KPOn4Jv1q4bI9hV0C9NUe2tTXS6/Vv3vbCY7lRR0kbJ65T5
c8CmpqJuASIJNrSXM/Q3NnnsY4kBYH0s5d2FgbASQvzrjuC2rngUg0EoPsrb
DEVRA2/BCJonw7aASiNCrSP92lkZdtYlax/pcoE/mQ4WSwySFmcFT7yFABEB
AAHNBlVzZXJJRMLAcgQQAQgAJgUCVEltzwYLCQgHAwIJED62JZ7fId8kBBUI
AgoDFgIBAhsDAh4BAAD0nQf9EtH9TC0JqSs8q194Zo244jjlJFM3EzxOSULq
0zbywlLORfyoo/O8jU/HIuGz+LT98JDtnltTqfjWgu6pS3ZL2/L4AGUKEoB7
OI6oIdRwzMc61sqI+Qpbzxo7rzufH4CiXZc6cxORUgL550xSCcqnq0q1mds7
h5roKDzxMW6WLiEsc1dN8IQKzC7Ec5wA7U4oNGsJ3TyI8jkIs0IhXrRCd26K
0TW8Xp6GCsfblWXosR13y89WVNgC+xrrJKTZEisc0tRlneIgjcwEUvwfIg2n
9cDUFA/5BsfzTW5IurxqDEziIVP0L44PXjtJrBQaGMPlEbtP5i2oi3OADVX2
XbvsRc7ATQRUSW3PAQgAkPnu5fps5zhOB/e618v/iF3KiogxUeRhA68TbvA+
xnFfTxCx2Vo14aOL0CnaJ8gO5yRSqfomL2O1kMq07N1MGbqucbmc+aSfoElc
+Gd5xBE/w3RcEhKcAaYTi35vG22zlZup4x3ElioyIarOssFEkQgNNyDf5AXZ
jdHLA6qVxeqAb/Ff74+y9HUmLPSsRU9NwFzvK3Jv8C/ubHVLzTYdFgYkc4W1
Uug9Ou08K+/4NEMrwnPFBbZdJAuUjQz2zW2ZiEKiBggiorH2o5N3mYUnWEmU
vqL3EOS8TbWo8UBIW3DDm2JiZR8VrEgvBtc9mVDUj/x+5pR07Fy1D6DjRmAc
9wARAQABwsBfBBgBCAATBQJUSW3SCRA+tiWe3yHfJAIbDAAA/iwH/ik9RKZM
B9Ir0x5mGpKPuqhugwrc3d04m1sOdXJm2NtD4ddzSEvzHwaPNvEvUl5v7FVM
zf6+6mYGWHyNP4+e7RtwYLlRpud6smuGyDSsotUYyumiqP6680ZIeWVQ+a1T
ThNs878mAJy1FhvQFdTmA8XIC616hDFpamQKPlpoO1a0wZnQhrPwT77HDYEE
a+hqY4Jr/a7ui40S+7xYRHKL/7ZAS4/grWllhU3dbNrwSzrOKwrA/U0/9t73
8Ap6JL71YymDeaL4sutcoaahda1pTrMWePtrCltz6uySwbZs7GXoEzjX3EAH
+6qhkUJtzMaE3YEFEoQMGzcDTUEfXCJ3zJw=
=yT9U
-----END PGP PUBLIC KEY BLOCK-----
`

const testMailboxPassword = "apple"
const testMailboxPasswordLegacy = "123"

const testToken = "d79ca194a22810a5363eeddfdef7dfbc327c6229"

const testEncryptedToken = `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v1.2.0
Comment: http://openpgpjs.org

wcBMA0fcZ7XLgmf2AQf/RxDfA7g85KzH4371D/jx6deJIXPOWAqgTlGQMsTt
yg4ny3phSC2An/bUXNEBm8UMXqqtS7O+S8n1GjkDrCOkxyC+HugOFQwtybzI
eRX0X0qqvR6ry940SNGjPfJJ4Z0FYSLJtT8YxqO38t38WAYV1j9mBBVPMPJF
r7cQXxEcQAd6NZWF1Cf5Ajuum/zFjbA10Ksbi1tC4fsdtHcS94h1GCfsdNQi
xxbAuoyNYX2wsc6WX8IcmDNn564ZoHfvf2tX4Csf+2czByyOPtfyCn1aee51
I40/I+65w8NfYEfzu7pbUcdo041Xg3lOhDNcuX/zANNw6zEWbE+12G5KVvwC
NNJgARWnwnOKtov2d73wGqNawn21SzA+zEd2mAPv1LPPIupW+0xOUSp5muov
aLEjcIuZeu+vyhXGZxIgoY4Bw8XCO9uWKZuzmqp+AOIP+kSi5aWnOaDFIOq0
B3KtZ33bMZeX
=mig5
-----END PGP MESSAGE-----
`

var (
	testPrivateKeyRing *KeyRing
	testPublicKeyRing  *KeyRing
)

var testIdentity = &Identity{
	Name:  "UserID",
	Email: "",
}

func init() {
	var err error
	if testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(testPrivateKey)); err != nil {
		panic(err)
	}

	if testPublicKeyRing, err = ReadArmoredKeyRing(strings.NewReader(testPublicKey)); err != nil {
		panic(err)
	}

	if err := testPrivateKeyRing.Unlock([]byte(testMailboxPassword)); err != nil {
		panic(err)
	}
}

func TestKeyRing_Decrypt(t *testing.T) {
	s, _, err := testPrivateKeyRing.DecryptString(testEncryptedToken)
	if err != nil {
		t.Fatal("Cannot decrypt token:", err)
	}

	if s != testToken {
		t.Fatalf("Invalid decrypted token: want %v but got %v", testToken, s)
	}
}

func TestKeyRing_Encrypt(t *testing.T) {
	encrypted, err := testPublicKeyRing.EncryptString(testToken, nil)
	if err != nil {
		t.Fatal("Cannot encrypt token:", err)
	}

	// We can't just check if encrypted == testEncryptedToken
	// Decrypt instead
	s, _, err := testPrivateKeyRing.DecryptString(encrypted)
	if err != nil {
		t.Fatal("Cannot decrypt token:", err)
	}

	if s != testToken {
		t.Fatalf("Invalid decrypted token: want %v but got %v", testToken, s)
	}
}

func TestKeyRing_ArmoredPublicKeyString(t *testing.T) {
	s, err := testPrivateKeyRing.ArmoredPublicKeyString()
	if err != nil {
		t.Fatal("Expected no error while getting armored public key, got:", err)
	}

	// Decode armored keys
	block, err := armor.Decode(strings.NewReader(s))
	if err != nil {
		t.Fatal("Expected no error while decoding armored public key, got:", err)
	}
	expected, err := armor.Decode(strings.NewReader(testPublicKey))
	if err != nil {
		t.Fatal("Expected no error while decoding expected armored public key, got:", err)
	}

	if expected.Type != block.Type {
		t.Fatalf("Invalid public key block type: expected %v, got %v", expected.Type, block.Type)
	}

	b, err := ioutil.ReadAll(block.Body)
	if err != nil {
		t.Fatal("Expected no error while reading armored public key body, got:", err)
	}
	eb, err := ioutil.ReadAll(expected.Body)
	if err != nil {
		t.Fatal("Expected no error while reading expected armored public key body, got:", err)
	}

	if bytes.Compare(eb, b) != 0 {
		t.Fatal("Invalid public key body: expected %v, got %v", eb, b)
	}
}
