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
	go build golang.org/x/mobile/cmd/gomobile
	go build golang.org/x/mobile/cmd/gobind
	PATH=$(pwd):$PATH
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
	if [ $TARGET = "android" ]; then
		JAVAPKG_FLAG="-javapkg=${ANDROID_JAVA_PKG}"
		OUT_EXTENSION="aar"
	else
		JAVAPKG_FLAG=""
		OUT_EXTENSION="framework"
	fi
	TARGET_DIR=${OUT_DIR}/${TARGET}
	TARGET_OUT_FILE=${TARGET_DIR}/${BUILD_NAME}.${OUT_EXTENSION}
	mkdir -p $TARGET_DIR
	printf "${green}Start Building ${TARGET} .. Location: ${TARGET_DIR} ${reset}\n\n"
	remove_dir $TARGET_OUT_FILE
	./gomobile bind -tags mobile -target $TARGET $JAVAPKG_FLAG -x -ldflags="-s -w" -o ${TARGET_OUT_FILE}  ${PACKAGES}
}

# import function, add internal package in the build
import()
{
    PACKAGES="${PACKAGES} $1"
}


## ======== Config ===============
# ==== Generic parameters ======

# output directory
OUT_DIR="./dist"

# name of the build output
BUILD_NAME="Gopenpgp"

ANDROID_JAVA_PKG="com.proton.${BUILD_NAME}"

# ==== Packages to included =====
PACKAGES=""
## crypto must be the first one, and the framework name better same with the first package name
import github.com/ProtonMail/gopenpgp/v2/crypto
import github.com/ProtonMail/gopenpgp/v2/armor
import github.com/ProtonMail/gopenpgp/v2/constants
import github.com/ProtonMail/gopenpgp/v2/models
import github.com/ProtonMail/gopenpgp/v2/subtle
import github.com/ProtonMail/gopenpgp/v2/helper

######## ======== Main ===========

# We get the needed go modules stated in the go.mod file
install_modules
install_gomobile
go env
echo "PATH=$PATH"
echo "gomobile:$(which gomobile)"

printf "Packages included : ${PACKAGES}\n"
## start building


# ================= Apple Builds ======================
# ========== iOS and Simulator =========
if [ $NB_INPUTS -ne 1 ] || [ $USER_INPUT = apple ]; then
# we build the framework for the ios sim on arm64 macs

build ios-simulator

# we build the framework for the ios devices
build ios

# ========== macOs ====================

# we build the framework for the macos devices

build macos

# ======== macOSUI ===============

# we build the framework for the macos-ui target

build macos-ui

# we join all platform's framework in a xcframework
XCFRAMEWORK_OUT_FILE=$OUT_DIR/$BUILD_NAME.xcframework
remove_dir $XCFRAMEWORK_OUT_FILE;
xcodebuild -create-xcframework \
 -framework $OUT_DIR/ios/$BUILD_NAME.framework \
 -framework $OUT_DIR/macos/$BUILD_NAME.framework \
 -framework $OUT_DIR/macos-ui/$BUILD_NAME.framework \
 -framework $OUT_DIR/ios-simulator/$BUILD_NAME.framework \
 -output $XCFRAMEWORK_OUT_FILE

fi


# ================  Android Build =====================
if [ $NB_INPUTS -ne 1 ] || [ $USER_INPUT = android ]; then
build android
fi

printf "${green}All Done. ${reset}\n\n"

trap - EXIT