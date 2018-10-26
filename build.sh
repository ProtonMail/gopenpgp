#!/bin/bash

SCRIPT_LOCATION=$(cd $(dirname $0);echo $PWD)

OUTPUT_PATH="dist"
ANDROID_OUT=${OUTPUT_PATH}/"Android"
IOS_OUT=${OUTPUT_PATH}/"iOS"
mkdir -p $ANDROID_OUT
mkdir -p $IOS_OUT

ln -s . vendor/src

# CHECK="${1-0}"
# if [ ${CHECK} -eq "1" ]; then
printf "\e[0;32mStart Building iOS framework .. Location: ${IOS_OUT} \033[0m\n\n"

GOPATH="$SCRIPT_LOCATION:$SCRIPT_LOCATION/vendor:$GOPATH" gomobile bind -target ios -o ${IOS_OUT}/Crypto.framework -ldflags="-s -w" gitlab.com/ProtonMail/go-pm-crypto/crypto gitlab.com/ProtonMail/go-pm-crypto/armor gitlab.com/ProtonMail/go-pm-crypto/constants gitlab.com/ProtonMail/go-pm-crypto/key gitlab.com/ProtonMail/go-pm-crypto/models

printf "\e[0;32mStart Building Android lib .. Location: ${ANDROID_OUT} \033[0m\n\n"

GOPATH="$SCRIPT_LOCATION:$SCRIPT_LOCATION/vendor:$GOPATH" gomobile bind -target android -javapkg com.proton.pmcrypto -o ${ANDROID_OUT}/pmcrypto.aar -ldflags="-s -w" gitlab.com/ProtonMail/go-pm-crypto/crypto gitlab.com/ProtonMail/go-pm-crypto/armor gitlab.com/ProtonMail/go-pm-crypto/constants gitlab.com/ProtonMail/go-pm-crypto/key gitlab.com/ProtonMail/go-pm-crypto/models

printf "\e[0;32mInstalling frameworks. \033[0m\n\n"

unlink vendor/src

printf "\e[0;32mAll Done. \033[0m\n\n"


