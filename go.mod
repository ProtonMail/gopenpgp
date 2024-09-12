module github.com/ProtonMail/gopenpgp/v3

go 1.21

toolchain go1.21.6

require (
	github.com/ProtonMail/go-crypto v1.1.0-alpha.5.0.20240912135802-28c613e7c719
	github.com/ProtonMail/go-mime v0.0.0-20230322103455-7d82a3887f2f
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
)

require (
	github.com/cloudflare/circl v1.4.0 // indirect
	github.com/davecgh/go-spew v1.1.0 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

replace github.com/cloudflare/circl v1.4.0 => github.com/lubux/circl v0.0.0-20240912122524-f16d68fe1630
replace github.com/cloudflare/circl v1.3.7 => github.com/lubux/circl v0.0.0-20240912122524-f16d68fe1630
