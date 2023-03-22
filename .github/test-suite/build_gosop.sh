cd gosop
echo "replace github.com/ProtonMail/gopenpgp/v2 => ../gopenpgp" >> go.mod
go get github.com/ProtonMail/gopenpgp/v2/crypto
go build .
