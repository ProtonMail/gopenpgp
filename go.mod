module github.com/ProtonMail/gopenpgp/v2

go 1.15

require (
	github.com/ProtonMail/go-crypto v0.0.0-20230217124315-7d5c6f04bbb8
	github.com/ProtonMail/go-mime v0.0.0-20221031134845-8fd9bc37cf08
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/mobile v0.0.0-20221110043201-43a038452099 // indirect
)

replace golang.org/x/mobile => github.com/ProtonMail/go-mobile v0.0.0-20210326110230-f181c70e4e2b
