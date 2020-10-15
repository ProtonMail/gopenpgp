#!/bin/bash

install_modules()
{
	printf "\e[0;32mStart installing go modules and their dependencies \033[0m\n\n"
	GO111MODULE=on
	go mod download
	printf "\e[0;32mDone \033[0m\n\n"
}

install_gomobile()
{
	printf "\e[0;32mInstalling gomobile fork\033[0m\n\n"
	go build golang.org/x/mobile/cmd/gomobile
	go build golang.org/x/mobile/cmd/gobind
	printf "\e[0;32mDone \033[0m\n\n"
	PATH=$(pwd):$PATH
}

# import function, add internal package in the build
import()
{
    PACKAGES="${PACKAGES} $1"
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
		OUT_EXTENSION="aar"
	else
		OUT_EXTENSION="framework"
	fi
	TARGET_DIR=${BUILD_DIR}/${TARGET}
	TARGET_OUT_FILE=${TARGET_DIR}/${BUILD_NAME}.${OUT_EXTENSION}
	mkdir -p $TARGET_DIR
	printf "\e[0;32mStart Building ${TARGET} .. Location: ${TARGET_DIR} \033[0m\n\n"
	remove_dir $TARGET_OUT_FILE
	gomobile bind -tags mobile -target $TARGET -x -o ${TARGET_OUT_FILE} -ldflags="${LDFLAGS}" ${PACKAGES}

}


## ======== Config ===============

# ==== Generic parameters ======

# output directory
BUILD_DIR="./build"

# linkage flags
LDFLAGS="'all=-s -w'"

# name of the build output
BUILD_NAME="Crypto"

# ==== Packages to include =====
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
echo "gomobile: $(which gomobile)"
echo "gobind: $(which gobind)"
printf "Packages included : ${PACKAGES}\n"
## start building
# ================= Apple Builds ======================
if [ "$#" -ne 1 ] || [ $1 = apple ]; then
# ========== iOS and Simulator =========

# we build the framework for the ios devices
build ios

# we make a copy of the framework for the simulator
IOSSIM_OUT=${BUILD_DIR}/"ios-simulator"
mkdir -p $IOSSIM_OUT
IOS_OUT_FILE=${BUILD_DIR}/ios/${BUILD_NAME}.framework
IOSSIM_OUT_FILE=${IOSSIM_OUT}/${BUILD_NAME}.framework
remove_dir $IOSSIM_OUT_FILE;

cp -R $IOS_OUT_FILE $IOSSIM_OUT_FILE;

# we remove the unwanted archs for ios and simulator
lipo $IOSSIM_OUT_FILE/Versions/A/Crypto -remove arm64 -output $IOSSIM_OUT_FILE/Versions/A/Crypto;
lipo $IOS_OUT_FILE/Versions/A/Crypto -remove x86_64 -output $IOS_OUT_FILE/Versions/A/Crypto;


# ========== macOs ====================

# we build the framework for the macos devices

build macos

# ======== macOSUI ===============

# we build the framework for the macos-ui target

build macos-ui

# we join all platform's framework in a xcframework
XCFRAMEWORK_OUT_FILE=$BUILD_DIR/$BUILD_NAME.xcframework
remove_dir $XCFRAMEWORK_OUT_FILE;

xcodebuild -create-xcframework  -framework $BUILD_DIR/ios/$BUILD_NAME.framework -framework $BUILD_DIR/macos/$BUILD_NAME.framework -framework $BUILD_DIR/macos-ui/$BUILD_NAME.framework -framework $BUILD_DIR/ios-simulator/$BUILD_NAME.framework -output $XCFRAMEWORK_OUT_FILE

fi
# ================  Android Build =====================
if [ "$#" -ne 1 ] || [ $1 = android ]; then
ANDROID_JAVA_PAG="com.proton.${ANDROID_OUT_FILE_NAME}"
build android

printf "\e[0;32mAll Done. \033[0m\n\n"
fi
