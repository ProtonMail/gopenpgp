package crypto

import (
	"bytes"
	"encoding/hex"
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

const exampleDetachedSignature = `-----BEGIN PGP SIGNATURE-----

wnEEABsIACcFAmSe4bEJkEHsytogdrSJFiEEamc2vcEGXMMaYxmDQezK2iB2tIkA
AIL40zuQXGBliZqje7eniv34NFZf2zQIE8gQOdcnWqFLlgg210RHjqqS2qGOuQyL
exN6Dbkaubvk6EhvTmYXIXnSAQ==
=EeGr
-----END PGP SIGNATURE-----`

const exampleInlineSignature = `-----BEGIN PGP MESSAGE-----

xA0DAAgbQezK2iB2tIkByxViAAAAAABtZXNzYWdlIHRvIHNpZ27CcQQAGwgAJwUC
ZJ7jVQmQQezK2iB2tIkWIQRqZza9wQZcwxpjGYNB7MraIHa0iQAA/+K//wXxUyVf
m50qAP92QZTqsHIokut9xP8Lp/ntSdKWBLdmoWHVpXElGpnIinSNt6NNjHj+S22u
QqO+M5PHk0cI
-----END PGP MESSAGE-----`

const exampleCleartextSignature = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

message to sign
-----BEGIN PGP SIGNATURE-----

wnEEARsKACcFAmSe5K0JkEHsytogdrSJFiEEamc2vcEGXMMaYxmDQezK2iB2tIkA
APwuHaxUQ7xX4WdqWm7WnipmbM/ARTJPESACNoFlw7p/aHuXw+nyolUeIRnadyle
0KepPKwDaTY+7Jk7/5kv7NiqAg==
-----END PGP SIGNATURE-----`

const exampleSplitMessage = `c1440361ce9c95894276da19cf0760b3a1150038c6d9ab20a5594fc9e32ce12009fb0a3ec12783b8efcf57521907d012786468567d736db82a9b160a598ea8decd762b982063
d2c0140104f3439588864ca36d6c15c0ae9364c706a869f13fc71987acd5061716914b03b4ef1884d67d19f28e9c29447fbd76781cd9b69bad22fc2b7eefd0d1b6c4e5d3f90368d19b5a2eb02cb1fb4d706f77feb1b200ac553cd872e1e695bafbac39fbf729f89a96aaf9fdef72c801545db2e627b357df18d05841f2fbd5aeb82b38db28a7f4cd946b17f98922fcbd78cf03b3ff7247918f381e61482960a9eec2192c64aa1a3eddbab486a7372c65e8f2c9b284f6b232cd3a4147fa374635cd1ad7e8b210334fce25c49cce99f91ff835dbfb3c6a27`

const exampleEncryptedDetachedMessage = `-----BEGIN PGP MESSAGE-----

wVQDYc6clYlCdtoZVaZe8pDekqVSnY9/wtXIPV92Yi1b/Nc0cxaw3CyG7xkpCbnc
V5NWsbpp0NaJ3Gxq/APdetC3iPG+AjM4xuWKhZWZ3/+bea/2q8jSOwF43weMcuQF
zXxGfqB9uLYsOXejBTO4oPDbuWH11SVibxa6k1X79l2+kf2dDgruhMk564h4SU6v
dbID
-----END PGP MESSAGE-----`

const exampleEncryptedDetachedSignatureMessage = `-----BEGIN PGP MESSAGE-----

wVQDYc6clYlCdtoZVaZe8pDekqVSnY9/wtXIPV92Yi1b/Nc0cxaw3CyG7xkpCbnc
V5NWsbpp0NaJ3Gxq/APdetC3iPG+AjM4xuWKhZWZ3/+bea/2q8jSpAHHbawcWmFq
ecrYdNNCv7KZS3ofScFXVuYWI8tc8sgaCUd2b82krn0dWRAzaxBuz+rJ99/jQa8U
GZSc+PaljzEvgR+GoQc5h8VJ58UmDXoN9VhWYKBBz1B1bkCu1vsDNS1yXk/XNi2e
BMEdvkP9hUOsJTO9e1qQLhmmEQlyHkmQGSyIHFNaYMI18RSUVmfZwZ7fsL/I07zp
nNWmL4dHU3Ba+56V
-----END PGP MESSAGE-----`

func ExamplePGPHandle_Encryption_password() {
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

func ExamplePGPHandle_Encryption_asymmetric() {
	// Encrypt data with a public key
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		return
	}
	pgp := PGP()
	encHandle, err := pgp.Encryption().
		Recipient(publicKey).
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

func ExamplePGPHandle_Encryption_signcrypt() {
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

func ExamplePGPHandle_Encryption_stream() {
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
	if err != nil {
		fmt.Println(err)
		return
	}
	if _, err = io.Copy(ptWriter, messageReader); err != nil {
		return
	}
	if err = ptWriter.Close(); err != nil {
		return
	}
	fmt.Println(ciphertextWriter.String())
}

func ExamplePGPHandle_Encryption_split() {
	// Split encrypted message into key packets and data packets.
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
	var keyPackets bytes.Buffer
	var dataPackets bytes.Buffer
	splitWriter := NewPGPSplitWriterKeyAndData(&keyPackets, &dataPackets)
	ptWriter, err := encHandle.EncryptingWriter(splitWriter, Bytes)
	if err != nil {
		return
	}
	if _, err = io.Copy(ptWriter, strings.NewReader("my message")); err != nil {
		return
	}
	if err = ptWriter.Close(); err != nil {
		return
	}
	fmt.Printf("%x\n", keyPackets.Bytes())
	fmt.Printf("%x\n", dataPackets.Bytes())
}

func ExamplePGPHandle_Encryption_detached() {
	// Produce encrypted detached signatures instead of
	// embedded signatures:
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
		DetachedSignature().
		New()
	if err != nil {
		return
	}
	var pgpMessage bytes.Buffer
	var pgpSignatureMessage bytes.Buffer
	splitWriter := NewPGPSplitWriterDetachedSignature(&pgpMessage, &pgpSignatureMessage)
	ptWriter, err := encHandle.EncryptingWriter(splitWriter, Armor)
	if err != nil {
		return
	}
	if _, err = io.Copy(ptWriter, strings.NewReader("my message")); err != nil {
		return
	}
	if err = ptWriter.Close(); err != nil {
		return
	}
	fmt.Println(pgpMessage.String())
	fmt.Println(pgpSignatureMessage.String())
}

func ExamplePGPHandle_Decryption_password() {
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

func ExamplePGPHandle_Decryption_asymmetric() {
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
	decrypted, err := decHandle.Decrypt([]byte(exampleEncryptedMessagePub), Armor)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(decrypted.String())
	// Output: my message
}

func ExamplePGPHandle_Decryption_signcrypt() {
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
	if err != nil {
		return
	}
	if sigErr := decrypted.SignatureError(); sigErr != nil {
		fmt.Println(sigErr)
		return
	} else {
		fmt.Println("OK")
	}
	fmt.Println(decrypted.String())
	// Output: OK
	// my message
}

func ExamplePGPHandle_Decryption_split() {
	// Decrypt key and data packet
	// separately.
	data := strings.Split(exampleSplitMessage, "\n")
	keyPacket, _ := hex.DecodeString(data[0])
	dataPacket, _ := hex.DecodeString(data[1])
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
		New()
	if err != nil {
		fmt.Println(err)
		return
	}
	sessionKey, err := decHandle.DecryptSessionKey(keyPacket)
	if err != nil {
		fmt.Println(err)
		return
	}
	decHandle, err = pgp.
		Decryption().
		SessionKey(sessionKey).
		VerificationKey(publicKey).
		DisableIntendedRecipients().
		New()
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypted, err := decHandle.Decrypt(dataPacket, Bytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	if sigErr := decrypted.SignatureError(); sigErr != nil {
		fmt.Println(sigErr)
		return
	} else {
		fmt.Println("OK")
	}
	fmt.Println(decrypted.String())
	// Output: OK
	// my message
}

func ExamplePGPHandle_Decryption_stream() {
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
	} else {
		fmt.Println("OK")
	}
	fmt.Println(decrypted.String())
	// Output: OK
	// my message
}

func ExamplePGPHandle_Decryption_detached() {
	// Decrypt armored encrypted message and verify an encrypted
	// detached signature.
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
	ciphertextReader := NewPGPSplitReader(
		strings.NewReader(exampleEncryptedDetachedMessage),
		strings.NewReader(exampleEncryptedDetachedSignatureMessage),
	)
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
	} else {
		fmt.Println("OK")
	}
	fmt.Println(decrypted.String())
	// Output: OK
	// my message
}

func ExamplePGPHandle_KeyGeneration_basic() {
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

func ExamplePGPHandle_KeyGeneration_profile() {
	// Generate a PGP key with the crypto-refresh profile
	pgp := PGPWithProfile(profile.RFC9580())
	genHandle := pgp.KeyGeneration().
		AddUserId("Max Mustermann", "max.mustermann@example.com").
		New()
	key, err := genHandle.GenerateKey()
	if err != nil {
		return
	}
	fmt.Println(key.Armor())
}

func ExamplePGPHandle_KeyGeneration_level() {
	// Generate a PGP key with the crypto-refresh profile
	// higher security level (Curve448)
	pgp := PGPWithProfile(profile.RFC9580())
	genHandle := pgp.KeyGeneration().
		AddUserId("Max Mustermann", "max.mustermann@example.com").
		New()
	key, err := genHandle.GenerateKeyWithSecurity(constants.HighSecurity)
	if err != nil {
		return
	}
	fmt.Println(key.Armor())
}

func ExamplePGPHandle_Sign_detached() {
	// Sign a plaintext with a private key
	// using a detached signatures.
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	signingMessage := []byte("message to sign")
	signer, _ := pgp.Sign().
		SigningKey(privateKey).
		Detached().
		New()
	signature, err := signer.Sign(signingMessage, Armor)
	if err != nil {
		return
	}
	fmt.Println(string(signature))
}

func ExamplePGPHandle_Sign_inline() {
	// Sign a plaintext with a private key
	// using a inline signature.
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	signingMessage := []byte("message to sign")
	signer, _ := pgp.Sign().
		SigningKey(privateKey).
		New()
	signatureMessage, err := signer.Sign(signingMessage, Armor)
	if err != nil {
		return
	}
	fmt.Println(string(signatureMessage))
}

func ExamplePGPHandle_Sign_cleartext() {
	// Sign a plaintext with a private key
	// using the cleartext signature framework.
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	signingMessage := []byte("message to sign")
	signer, _ := pgp.Sign().
		SigningKey(privateKey).
		New()
	signatureMessage, err := signer.SignCleartext(signingMessage)
	if err != nil {
		return
	}
	fmt.Println(string(signatureMessage))
}

func ExamplePGPHandle_Sign_stream() {
	// Sign a plaintext with a private key
	// using a inline signature with streaming.
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	signer, _ := pgp.Sign().
		SigningKey(privateKey).
		New()
	var signedMessage bytes.Buffer
	messageWriter, err := signer.SigningWriter(&signedMessage, Armor)
	if err != nil {
		return
	}
	if _, err = io.Copy(messageWriter, strings.NewReader("message to sign")); err != nil {
		return
	}
	if err = messageWriter.Close(); err != nil {
		return
	}
	fmt.Println(signedMessage.String())
}

func ExamplePGPHandle_Verify_detached() {
	// Verify detached signature with a public key.
	verifyMessage := []byte("message to sign")
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	pgp := PGP()
	verifier, _ := pgp.Verify().
		VerificationKey(publicKey).
		New()
	verifyResult, err := verifier.VerifyDetached(verifyMessage, []byte(exampleDetachedSignature), Armor)
	if err != nil {
		fmt.Println(err)
		return
	}
	if sigErr := verifyResult.SignatureError(); sigErr != nil {
		fmt.Println(sigErr)
	} else {
		fmt.Println("OK")
	}
	// Output: OK
}

func ExamplePGPHandle_Verify_inline() {
	// Verify a inline signed message with a public key.
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	pgp := PGP()
	verifier, _ := pgp.Verify().
		VerificationKey(publicKey).
		New()
	verifyResult, err := verifier.VerifyInline([]byte(exampleInlineSignature), Armor)
	if err != nil {
		fmt.Println(err)
		return
	}
	if sigErr := verifyResult.SignatureError(); sigErr != nil {
		fmt.Println(sigErr)
	} else {
		fmt.Println("OK")
	}
	fmt.Println(verifyResult.String())
	// Output: OK
	// message to sign
}

func ExamplePGPHandle_Verify_cleartext() {
	// Verify a cleartext signed message with a public key.
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	pgp := PGP()
	verifier, _ := pgp.Verify().
		VerificationKey(publicKey).
		New()
	verifyResult, err := verifier.VerifyCleartext([]byte(exampleCleartextSignature))
	if err != nil {
		fmt.Println(err)
		return
	}
	if sigErr := verifyResult.SignatureError(); sigErr != nil {
		fmt.Println(sigErr)
	} else {
		fmt.Println("OK")
	}
	fmt.Println(string(verifyResult.Cleartext()))
	// Output: OK
	// message to sign
}

func ExamplePGPHandle_Verify_stream() {
	// Verify a inline signed message with a public key using streaming.
	publicKey, err := NewKeyFromArmored(examplePubKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	pgp := PGP()
	verifier, _ := pgp.Verify().
		VerificationKey(publicKey).
		New()
	messageReader, err := verifier.VerifyingReader(nil, strings.NewReader(exampleInlineSignature), Armor)
	if err != nil {
		fmt.Println(err)
		return
	}
	verifyResult, err := messageReader.ReadAllAndVerifySignature()
	if err != nil {
		fmt.Println(err)
		return
	}
	if sigErr := verifyResult.SignatureError(); sigErr != nil {
		fmt.Println(sigErr)
	} else {
		fmt.Println("OK")
	}
	fmt.Println(verifyResult.String())
	// Output: OK
	// message to sign
}

func ExamplePGPHandle_LockKey() {
	// Encrypt secret material in a private key with a passphrase.
	privateKey, err := NewKeyFromArmored(examplePrivKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer privateKey.ClearPrivateParams()
	pgp := PGP()
	lockedKey, err := pgp.LockKey(privateKey, []byte("password"))
	if err != nil {
		fmt.Println(err)
		return
	}
	locked, _ := lockedKey.IsLocked()
	fmt.Println(locked)
	// Output: true
}
