VERSION=$(awk '/^module github.com\/ProtonMail\/gopenpgp\/v[0-9]+/ {print $NF}' gopenpgp/go.mod | awk -F'v' '{print $2}')

cd gosop
echo "replace github.com/ProtonMail/gopenpgp/v${VERSION} => ../gopenpgp" >> go.mod
go get github.com/ProtonMail/gopenpgp/v${VERSION}/crypto
go build .
