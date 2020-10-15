module github.com/ProtonMail/gopenpgp/v2/build_iOS

go 1.15

require (
	github.com/ProtonMail/gopenpgp/v2 latest
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200416114516-1fa7f403fb9c

replace golang.org/x/mobile => github.com/zhj4478/mobile latest
