DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
GOPATH="$DIR" glide up
GOPATH="$DIR:$DIR/vendor:$GOPATH" gomobile init -ndk $ANDROID_NDK
