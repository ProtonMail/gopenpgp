#!/bin/bash
SCRIPT_LOCATION=$(cd $(dirname $0); echo $PWD)

source ~/.zshenv

printf "\e[0;32mStart installing vendor \033[0m\n\n"
GO111MODULE=on
go mod vendor
GO111MODULE=off
printf "\e[0;32mDone \033[0m\n\n"

OUTPUT_PATH="dist"

ANDROID_OUT=${OUTPUT_PATH}/"Android"
ANDROID_OUT_FILE_NAME="gopenpgp"
ANDROID_OUT_FILE=${ANDROID_OUT}/${ANDROID_OUT_FILE_NAME}.aar
ANDROID_JAVA_PAG="com.proton.${ANDROID_OUT_FILE_NAME}"

IOS_OUT=${OUTPUT_PATH}/"iOS"
IOS_OUT_FILE_NAME="Crypto"
IOS_OUT_FILE=${IOS_OUT}/${IOS_OUT_FILE_NAME}.framework

PACKAGE_PATH=github.com/ProtonMail/gopenpgp

mkdir -p $ANDROID_OUT
mkdir -p $IOS_OUT

install() 
{
    INSTALL_NAME=$1
    FROM_PATH=$2
    INSTALL_PATH=$3
    if [[ -z "${INSTALL_PATH}" ]]; then
        printf "\e[0;32m ${INSTALL_NAME} project path is undefined! ignroe this !\033[0m\n";
    else 
        printf "\n\e[0;32mDo you wise to install the library into ${INSTALL_NAME} project \033[0m\n"
        printf "\e[0;37m${INSTALL_NAME} Project Path: \033[0m" 
        printf "\e[0;37m${INSTALL_PATH} \033[0m" 
        printf "\n"
        while true; do
            read -p "[Yy] or [Nn]:" yn
            case $yn in
                [Yy]* )
                    printf "\e[0;32m  Installing .... \033[0m\n";
                    cp -rf ${FROM_PATH} ${INSTALL_PATH}/
                    printf "\n\e[0;32mInstalled \033[0m\n\n"
                    break;;
                [Nn]* ) exit;;
                * ) echo "Please answer yes or no.";;
            esac
        done
    fi
}

# import function, add internal package in the build
import()
{
    PACKAGES+=" ${PACKAGE_PATH}/v2/$1"
}

external() 
{
    PACKAGES+=" $1"
}

######## MARK -- Main

#flags
DFLAGS="-s -w"

#add internal package 
## crypto must be the first one, and the framework name better same with the first package name
import crypto 
import armor 
import constants 
import models 
import subtle 
import helper

## add external package
if [[ $1 != '' ]]; then
external $1
fi

printf "${PACKAGES}\n"
## start building

printf "\e[0;32mStart Building iOS framework .. Location: ${IOS_OUT} \033[0m\n\n"
## tags - mobile tag will filter unsupported functions
# gomobile bind -tags mobile -target ios -o ${IOS_OUT_FILE} -ldflags="${DFLAGS}" ${PACKAGES}
# install iOS  ${IOS_OUT_FILE} ${IOS_PROJECT_PATH}

printf "\e[0;32mStart Building Android lib .. Location: ${ANDROID_OUT} \033[0m\n\n"
gomobile bind -tags mobile -target android -javapkg ${ANDROID_JAVA_PAG} -o ${ANDROID_OUT_FILE} -ldflags="${DFLAGS}" ${PACKAGES}
# install Android ${ANDROID_OUT} ${ANDROID_PROJECT_PATH}

printf "\e[0;32mInstalling frameworks. \033[0m\n\n"

printf "\e[0;32mAll Done. \033[0m\n\n"