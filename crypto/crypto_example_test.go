package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

const examplePubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xiYEZIbSkxsHknQrXGfb+kM2iOsOvin8yE05ff5hF8KE6k+saspAZc0VdXNlciA8
dXNlckB0ZXN0LnRlc3Q+wocEExsIAD0FAmSG0pMJkEHsytogdrSJFiEEamc2vcEG
XMMaYxmDQezK2iB2tIkCGwMCHgECGQECCwcCFQgCFgADJwcCAABTnme46ymbAs0X
7tX3xWu+9O+LLdM0aAUyV6FwUNWcy47IfmTunwdqHZ2CbUGLLb+OR/9yci1aIHDJ
xXmJh3kj9wDOJgRkhtKTGX6Xe04jkL+7ikivpOB0/ZSq+fnZr2+76Mf/InbOrpxJ
wnQEGBsIACoFAmSG0pMJkEHsytogdrSJFiEEamc2vcEGXMMaYxmDQezK2iB2tIkC
GwwAAMJizYj3AFqQi70eHGzhHcmr0XwnsAfLGw0vQaiZn6HGITQw5nBGvXQPF9Vp
FpsXV9x/08dIdfZLAQVdQowgeBsxCw==
=JIkN
-----END PGP PUBLIC KEY BLOCK-----`

const examplePrivKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xUkEZIbSkxsHknQrXGfb+kM2iOsOvin8yE05ff5hF8KE6k+saspAZQCy/kfFUYc2
GkpOHc42BI+MsysKzk4ofjBAfqM+bb7goQ3hzRV1c2VyIDx1c2VyQHRlc3QudGVz
dD7ChwQTGwgAPQUCZIbSkwmQQezK2iB2tIkWIQRqZza9wQZcwxpjGYNB7MraIHa0
iQIbAwIeAQIZAQILBwIVCAIWAAMnBwIAAFOeZ7jrKZsCzRfu1ffFa77074st0zRo
BTJXoXBQ1ZzLjsh+ZO6fB2odnYJtQYstv45H/3JyLVogcMnFeYmHeSP3AMdJBGSG
0pMZfpd7TiOQv7uKSK+k4HT9lKr5+dmvb7vox/8ids6unEkAF1v8fCKogIrtBWVT
nVbwnovjM3LLexpXFZSgTKRcNMgPRMJ0BBgbCAAqBQJkhtKTCZBB7MraIHa0iRYh
BGpnNr3BBlzDGmMZg0HsytogdrSJAhsMAADCYs2I9wBakIu9Hhxs4R3Jq9F8J7AH
yxsNL0GomZ+hxiE0MOZwRr10DxfVaRabF1fcf9PHSHX2SwEFXUKMIHgbMQs=
=bJqd
-----END PGP PRIVATE KEY BLOCK-----`

const exampleEncryptedMessagePw = `-----BEGIN PGP MESSAGE-----

wy4ECQMIP4yfOrrWtD/g8JituG2N1xeV1o6Frdc3yn7JRoUMv0E69MyI/ito/OH2
0jsBi1NQPKaykn/nSxv+6xzAEWw2lZ6g6hy/gAGgbYy64Fkh652WMvjO9KKDZycB
orleBckXgArj64+2Kw==
-----END PGP MESSAGE-----`

const exampleEncryptedMessagePub = `-----BEGIN PGP MESSAGE-----

wUQDYc6clYlCdtoZPfr2cdbY5lVXC+J7/4CpjCocMlEqs739c5cu6rwx8yUZByKm
a/HB5JEf9oIsN/ekyHTmcftfTetwiNI7AfuPTGQYB3/PtamMToIClX5Ca+eDb6iU
VS0r4gpTv5iIvl9+k4sbSvxwjNMLBy9DyB+mlFc3OZ5dtFk=
-----END PGP MESSAGE-----`

const exampleEncryptedAndSigned = `-----BEGIN PGP MESSAGE-----

wUQDYc6clYlCdtoZgMQH5tynaMh60pY+uo3KuXzCM+bDkO1VqrL5IBRQWWMZB/2r
H8be1jZayJ8a1F+FG6Xs+LO2INR4lNLAFAHoLWu2En755DDZJwQwnDQ6Gywq26aq
STVC0Bt+srqxxOKJJFA2lN4tlVsn1pKsgaqO6s52JDFlT0OijF8wgz/kfc/ZwT7Z
EBdqURMaF3wUlQ5nX2/ZDQJNfU/d79W0+8IQ7QrVhVQuV7sub7EbpqSuFTwqPt73
jsLFlYxlYsgaKCHsmVVJWb1uIdPzHXXajTVPa1aRkkyCYMayXJEWOu7+HoW0Ipk1
piIFyQpQFvj9RAwuKaGQUfb5KRP1fegjwZd0/8TWDfLPuD2Fc3LBicxpI1Hk
-----END PGP MESSAGE-----`

func ExamplePGPHandle_Encryption() {
	// Encrypt data with a password
	password := []byte("hunter2")
	pgp := PGP()
	encHandle, err := pgp.Encryption().
		Password(password).
		New()
	if err != nil {
		return
	}
	pgpMessage, err := encHandle.Encrypt([]byte("my message"))
	if err != nil {
		return
	}
	armored, err := pgpMessage.Armor()
	if err != nil {
		return
	}
	fmt.Println(armored)
}

func ExamplePGPHandle_Encryption_second() {
	// Encrypt data with a public key
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		return
	}
	pgp := PGP()
	encHandle, err := pgp.Encryption().
		Recipient(publicKey).
		New()
	pgpMessage, err := encHandle.Encrypt([]byte("my message"))
	if err != nil {
		return
	}
	armored, err := pgpMessage.Armor()
	if err != nil {
		return
	}
	fmt.Println(armored)
}

func ExamplePGPHandle_Encryption_third() {
	// Encrypt data with a public key
	// and sign with private key
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		return
	}
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	encHandle, err := pgp.Encryption().
		Recipient(publicKey).
		SigningKey(privateKey).
		New()
	pgpMessage, err := encHandle.Encrypt([]byte("my message"))
	if err != nil {
		return
	}
	armored, err := pgpMessage.Armor()
	if err != nil {
		return
	}
	fmt.Println(armored)
}

func ExamplePGPHandle_Encryption_fourth() {
	// Encrypt data with a public key
	// and sign with private key streaming
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		return
	}
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	encHandle, err := pgp.Encryption().
		Recipient(publicKey).
		SigningKey(privateKey).
		New()
	if err != nil {
		return
	}
	messageReader := strings.NewReader("my message")
	var ciphertextWriter bytes.Buffer
	ptWriter, err := encHandle.EncryptingWriter(&ciphertextWriter, Armor)
	if io.Copy(ptWriter, messageReader); err != nil {
		return
	}
	if err = ptWriter.Close(); err != nil {
		return
	}
	fmt.Println(ciphertextWriter.String())
}

func ExamplePGPHandle_Decryption() {
	// Decrypt data with a password
	pgp := PGP()
	decHandle, err := pgp.
		Decryption().
		Password([]byte("hunter2")).
		New()
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypted, err := decHandle.Decrypt([]byte(exampleEncryptedMessagePw), Armor)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(decrypted.Bytes()))
	// Output: my message
}

func ExamplePGPHandle_Decryption_second() {
	// Decrypt armored encrypted message using
	// the private key and obtain the plaintext
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	decHandle, err := pgp.
		Decryption().
		DecryptionKey(privateKey).
		New()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer decHandle.ClearPrivateParams()
	decrypted, err := decHandle.Decrypt([]byte(exampleEncryptedMessagePub), Armor)
	fmt.Println(string(decrypted.Bytes()))
	// Output: my message
}

func ExamplePGPHandle_Decryption_third() {
	// Decrypt armored encrypted message using
	// the private key and obtain the plaintext
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	decHandle, err := pgp.
		Decryption().
		DecryptionKey(privateKey).
		VerificationKey(publicKey).
		New()
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypted, err := decHandle.Decrypt([]byte(exampleEncryptedAndSigned), Armor)
	if sigErr := decrypted.SignatureError(); sigErr != nil {
		fmt.Println(sigErr)
		return
	}
	fmt.Println(string(decrypted.Bytes()))
	// Output: my message
}

func ExamplePGPHandle_Decryption_fourth() {
	// Decrypt armored encrypted message using
	// the private key and obtain the plaintext with streaming
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		return
	}
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	decHandle, err := pgp.
		Decryption().
		DecryptionKey(privateKey).
		VerificationKey(publicKey).
		New()
	if err != nil {
		fmt.Println(err)
		return
	}
	ciphertextReader := strings.NewReader(exampleEncryptedAndSigned)
	ptReader, err := decHandle.DecryptingReader(ciphertextReader, Armor)
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypted, err := ptReader.ReadAllAndVerifySignature()
	if err != nil {
		fmt.Println(err)
		return
	}
	if sigErr := decrypted.SignatureError(); sigErr != nil {
		fmt.Println(sigErr)
		return
	}
	fmt.Println(string(decrypted.Bytes()))
	// Output: my message
}

func ExamplePGPHandle_KeyGeneration() {
	pgp := PGP()
	// Generate a PGP key
	genHandle := pgp.KeyGeneration().
		AddUserId("Max Mustermann", "max.mustermann@example.com").
		New()
	key, err := genHandle.GenerateKey()
	if err != nil {
		return
	}
	fmt.Println(key.Armor())
}

func ExamplePGPHandle_KeyGeneration_second() {
	// Generate a PGP key with the crypto-refresh profile
	pgp := PGPWithProfile(profile.CryptoRefresh())
	genHandle := pgp.KeyGeneration().
		AddUserId("Max Mustermann", "max.mustermann@example.com").
		New()
	key, err := genHandle.GenerateKey()
	if err != nil {
		return
	}
	fmt.Println(key.Armor())
}

func ExamplePGPHandle_KeyGeneration_third() {
	// Generate a PGP key with the crypto-refresh profile
	// higher security level (Curve448)
	pgp := PGPWithProfile(profile.CryptoRefresh())
	genHandle := pgp.KeyGeneration().
		AddUserId("Max Mustermann", "max.mustermann@example.com").
		New()
	key, err := genHandle.GenerateKeyWithSecurity(constants.HighSecurity)
	if err != nil {
		return
	}
	fmt.Println(key.Armor())
}
