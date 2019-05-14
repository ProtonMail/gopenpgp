# GopenPGP Wrapper Library

## Download/Install

Manually `git clone` the repository into `$GOPATH/src/github.com/ProtonMail/go-pm-crypto`.

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

### Generate key

### Sign

### Detached signatures
