module github.com/ProtonMail/gopenpgp

go 1.12

require (
	github.com/ProtonMail/go-mime v0.0.0-20190501141126-dc270ae56b61
	github.com/Sirupsen/logrus v0.0.0-20180904202135-3791101e143b // indirect
	github.com/stretchr/testify v1.3.0
	golang.org/x/crypto v0.0.0-20190513172903-22d7a77e9e5f
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20190427044656-efb430e751f2
