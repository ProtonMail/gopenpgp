module github.com/ProtonMail/gopenpgp/v2

go 1.15

require (
	github.com/ProtonMail/go-crypto v0.0.0-20210428141323-04723f9f07d7
	github.com/ProtonMail/go-mime v0.0.0-20190923161245-9b5a4261663a
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/mobile v0.0.0-20200801112145-973feb4309de
)

replace golang.org/x/mobile => github.com/ProtonMail/go-mobile v0.0.0-20210326110230-f181c70e4e2b
