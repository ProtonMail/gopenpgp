cd gosop
echo "replace github.com/ProtonMail/gopenpgp/v3 => ../gopenpgp" >> go.mod
go get github.com/ProtonMail/gopenpgp/v3/crypto
go build .
