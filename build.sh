#!/bin/bash

USER_INPUT=$1
NB_INPUTS=$#

set -ue pipefail  # End the script if any command, or intermediate command,
                  # returns an error code.

trap failed_build EXIT

# Colors for terminal display
red="\e[0;31m"
green="\e[0;32m"
reset="\033[0m"

# Trap in case something went wrong
failed_build() {
    printf "${red}The build failed!\nRun 'make clean' before retrying...\n${reset}"
}

install_modules()
{
	printf "${green}Start installing go modules and their dependencies ${reset}\n\n"
	GO111MODULE=on go mod download
	printf "${green}Done ${reset}\n\n"
}

install_gomobile()
{
	printf "${green}Installing gomobile fork${reset}\n\n"
	
	go get golang.org/x/mobile/cmd/gomobile@latest
	go get golang.org/x/mobile/cmd/gobind@latest
	
	go build golang.org/x/mobile/cmd/gomobile
	go build golang.org/x/mobile/cmd/gobind
	PATH=$(pwd):$PATH
	printf "${green}Done ${reset}\n\n"
}


get_modules(){
	printf "${green}Start installing go modules and their dependencies ${reset}\n\n"
	GO111MODULE=on go mod download
	printf "${green}Done ${reset}\n\n"
}


remove_dir()
{
	DIR=$1
	if [ -d "$DIR" ]; then
		printf "removing old $DIR\n"
		rm -rf $DIR
	fi
}

build()
{
	TARGET=$1
	OUTPUT_DIR=$2
	TAGS="mobile"
	if [ $TARGET = "android" ]; then
		JAVAPKG_FLAG="-javapkg=com.proton.gopenpgp"
		OUT_EXTENSION="aar"
	else
		JAVAPKG_FLAG=""
		OUT_EXTENSION="xcframework"
		TAGS="$TAGS,ios"
	fi
	TARGET_DIR=${OUT_DIR}/${OUTPUT_DIR}
	TARGET_OUT_FILE=${TARGET_DIR}/${BUILD_NAME}.${OUT_EXTENSION}
	mkdir -p $TARGET_DIR
	printf "${green}Start Building ${TARGET} .. Location: ${TARGET_DIR} ${reset}\n\n"
	remove_dir $TARGET_OUT_FILE
	./gomobile bind -tags $TAGS -target $TARGET $JAVAPKG_FLAG -x -ldflags="-s -w " -o ${TARGET_OUT_FILE}  ${PACKAGES}
}

# import function, add internal package in the build
import()
{
    PACKAGES="${PACKAGES} $1"
}


## ======== Config ===============

# ==== Generic parameters ======

# output directory
OUT_DIR="dist"

# name of the build output
BUILD_NAME="gopenpgp"

# ==== Packages to included =====
PACKAGES=""
## crypto must be the first one, and the framework name better same with the first package name
import github.com/ProtonMail/gopenpgp/v3/crypto
import github.com/ProtonMail/gopenpgp/v3/armor
import github.com/ProtonMail/gopenpgp/v3/constants
import github.com/ProtonMail/gopenpgp/v3/mime
import github.com/ProtonMail/gopenpgp/v3/mobile
import github.com/ProtonMail/gopenpgp/v3/profile

######## ======== Main ===========

install_modules
install_gomobile

get_modules

go env
echo "PATH=$PATH"
echo "gomobile:$(which gomobile)"

printf "Packages included : ${PACKAGES}\n"
## start building


# ================= Apple Builds ======================
# we build the framework for the ios devices and simulator
if [ $NB_INPUTS -ne 1 ] || [ $USER_INPUT = apple ]; then
build ios,iossimulator,macos apple
fi

# ================  Android Build =====================
if [ $NB_INPUTS -ne 1 ] || [ $USER_INPUT = android ]; then
build android android
fi

printf "${green}All Done. ${reset}\n\n"


trap - EXIT