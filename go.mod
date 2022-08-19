module github.com/ProtonMail/gopenpgp/v2

go 1.15

require (
	github.com/ProtonMail/go-crypto v0.0.0-20220819082139-33af46df2953
	github.com/ProtonMail/go-mime v0.0.0-20220302105931-303f85f7fe0f
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/mobile v0.0.0-20200801112145-973feb4309de
)

replace golang.org/x/mobile => github.com/ProtonMail/go-mobile v0.0.0-20210326110230-f181c70e4e2b
