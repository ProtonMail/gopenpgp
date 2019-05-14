# GopenPGP Wrapper Library

## Download/Install

Run `go get -u github.com/ProtonMail/gopenpgp`, or manually `git clone` the
repository into `$GOPATH/src/github.com/ProtonMail/gopenpgp`.

This library is meant to be used together with https://github.com/ProtonMail/crypto.

## Using with Go Mobile

Setup Go Mobile and build/bind the source code:

Go Mobile repo: https://github.com/golang/mobile  
Go Mobile wiki: https://github.com/golang/go/wiki/Mobile

1. Install Go: `brew install go`
2. Install Gomobile: `go get -u golang.org/x/mobile/cmd/gomobile`
3. Install Gobind: `go install golang.org/x/mobile/cmd/gobind`
4. Install Android SDK and NDK using Android Studio
5. Set env: `export ANDROID_HOME="/AndroidSDK"` (path to your SDK)
6. Init gomobile: `gomobile init -ndk /AndroidSDK/ndk-bundle/` (path to your NDK)

7. Build examples:  
   `gomobile build -target=android  #or ios`

   Bind examples:  
   `gomobile bind -target ios -o frameworks/name.framework`  
   `gomobile bind -target android`

   The bind will create framework for iOS and jar&aar files for Android (x86_64 and ARM).

## Other notes

This project uses glide to setup vendors.

Interfacing between Go and Swift:
https://medium.com/@matryer/tutorial-calling-go-code-from-swift-on-ios-and-vice-versa-with-gomobile-7925620c17a4.

If you use build.sh, you may need to modify the paths in it.

## Examples

### Set up

### Encrypt and decrypt

Encryption and decryption will use the AES256 algorithm by default.

#### Encrypt / Decrypt with password
```
var pgp = GopenPGP{}

const password = "my secret password"

// Encrypt data with password
armor, err := pgp.EncryptMessageWithPassword("my message", password)

// Decrypt data with password
message, err := pgp.DecryptMessageWithPassword(armor, password)
```

#### Encrypt / Decrypt with PGP keys
```
// put keys in backtick (``) to avoid errors caused by spaces or tabs
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key

const passphrase = `the passphrase of the private key` // what the privKey is encrypted with

privateKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(privkey))
publicKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(pubkey))

// encrypt message using public key and can be optionally signed using private key and passphrase
armor, err := pgp.EncryptMessage("plain text", publicKeyRing, privateKeyRing, passphrase, false)
// OR
privateKeyRing.Unlock([]byte(passphrase)) // if private key is locked with passphrase
armor, err := publicKeyRing.EncryptString("plain text", privateKeyRing)

// decrypt armored encrypted message using the private key and the passphrase of the private key
plainText, err := pgp.DecryptMessage(armor, privateKeyRing, passphrase)
// OR
signedText, err := privateKeyRing.DecryptString(armor)
plainText = signedText.String

```

### Generate key
Keys are generated with the `GenerateKey` function, that returns the armored key as a string and a potential error.  
The library supports RSA with different key lengths or Curve25519 keys.
```
var pgp = GopenPGP{}

var (
  localPart = "name.surname"
  domain = "example.com"
  passphrase = "LongSecret"
  rsaBits = 2048
  ecBits = 256
)

// RSA
rsaKey, err := pgp.GenerateKey(localPart, domain, passphrase, "rsa", rsaBits)

// Curve 25519
ecKey, err := pgp.GenerateKey(localPart, domain, passphrase, "x25519", ecBits)
```

### Sign

### Detached signatures
