module github.com/ProtonMail/gopenpgp/v2

go 1.12

require (
	github.com/ProtonMail/go-mime v0.0.0-20190923161245-9b5a4261663a
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.2.2
	golang.org/x/crypto v0.0.0-20190513172903-22d7a77e9e5f
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20191122234321-e77a1f03baa0
