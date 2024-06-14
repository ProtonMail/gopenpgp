VERSION=$(awk '/^module github.com\/ProtonMail\/gopenpgp\/v[0-9]+/ {print $NF}' gopenpgp/go.mod | awk -F'v' '{print $2}')

if [ "$VERSION" -eq 3 ]; then
  echo "gosop-gopenpgp-v3"
else
  echo "main"
fi