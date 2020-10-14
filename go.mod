module github.com/ProtonMail/gopenpgp/v2

go 1.12

require (
	github.com/ProtonMail/go-mime v0.0.0-20190923161245-9b5a4261663a
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/mobile v0.0.0-20200801112145-973feb4309de // indirect
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200416114516-1fa7f403fb9c

replace golang.org/x/mobile => github.com/zhj4478/mobile v0.0.0-20201014085805-7a2d68bf792f
