module github.com/ProtonMail/gopenpgp/v2

go 1.13

require (
	github.com/ProtonMail/go-mime v0.0.0-20190923161245-9b5a4261663a
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.4.0
	go-encrypted-search v0.0.0-00010101000000-000000000000 // indirect
	go-srp v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/crypto v0.0.0-20191111213947-16651526fdb4
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200416114516-1fa7f403fb9c

replace go-srp => ../../../go-srp

replace go-encrypted-search => ../../../go-encrypted-search
