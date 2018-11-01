#!/bin/bash

SCRIPT_LOCATION=$(cd $(dirname $0);echo $PWD)

OUTPUT_PATH="dist"
ANDROID_OUT=${OUTPUT_PATH}/"Android"
IOS_OUT=${OUTPUT_PATH}/"iOS"
mkdir -p $ANDROID_OUT
mkdir -p $IOS_OUT
# CHECK="${1-0}"
# if [ ${CHECK} -eq "1" ]; then
printf "\e[0;32mStart Building iOS framework .. Location: ${IOS_OUT} \033[0m\n\n"
PACKAGE_PATH=github.com/ProtonMail/go-pm-crypto

gomobile bind -target ios -o ${IOS_OUT}/pmcrypto.framework $PACKAGE_PATH/crypto $PACKAGE_PATH/armor $PACKAGE_PATH/constants $PACKAGE_PATH/key $PACKAGE_PATH/models

printf "\e[0;32mStart Building Android lib .. Location: ${ANDROID_OUT} \033[0m\n\n"

gomobile bind -target android -javapkg com.proton.pmcrypto -o ${ANDROID_OUT}/pmcrypto.aar $PACKAGE_PATH/crypto $PACKAGE_PATH/armor $PACKAGE_PATH/constants $PACKAGE_PATH/key $PACKAGE_PATH/models 

printf "\e[0;32mInstalling frameworks. \033[0m\n\n"

printf "\e[0;32mAll Done. \033[0m\n\n"


