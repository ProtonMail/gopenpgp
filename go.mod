module github.com/ProtonMail/gopenpgp/v2

go 1.15

require (
	github.com/ProtonMail/go-crypto v0.0.0-20201208171014-cdb7591792e2
	github.com/ProtonMail/go-mime v0.0.0-20190923161245-9b5a4261663a
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.4.0
	golang.org/x/mobile v0.0.0-20200801112145-973feb4309de
)

replace golang.org/x/mobile => github.com/ProtonMail/go-mobile v0.0.0-20201014085805-7a2d68bf792f
