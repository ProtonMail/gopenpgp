module github.com/ProtonMail/gopenpgp/v2/build_iOS

go 1.15

require (
	github.com/ProtonMail/gopenpgp/v2 v2.0.1
	golang.org/x/exp v0.0.0-20190731235908-ec7cb31e5a56 // indirect
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200416114516-1fa7f403fb9c

replace golang.org/x/mobile => github.com/zhj4478/mobile v0.0.0-20201014085805-7a2d68bf792f
