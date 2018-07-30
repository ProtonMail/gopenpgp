#!/bin/bash

SCRIPT_LOCATION=$(cd $(dirname $0);echo $PWD)

OUTPUT_PATH="bin"
ANDROID_OUT=${OUTPUT_PATH}/"Android"
IOS_OUT=${OUTPUT_PATH}/"iOS"

# CHECK="${1-0}"
# if [ ${CHECK} -eq "1" ]; then
printf "\e[0;32mStart Building iOS framework .. Location: ${IOS_OUT} \033[0m\n\n"

gomobile bind -target ios -o ${IOS_OUT}/PM.framework


printf "\e[0;32mStart Building Android lib .. Location: ${ANDROID_OUT} \033[0m\n\n"

gomobile bind -target android -o ${ANDROID_OUT}/PM.aar


printf "\e[0;32mInstalling frameworks. \033[0m\n\n"

printf "\e[0;32mAll Done. \033[0m\n\n"


