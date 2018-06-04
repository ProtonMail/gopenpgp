setup gomobile and build/bind the source code:

Gomobile repo: https://github.com/golang/mobile 
Gomobile wiki: https://github.com/golang/go/wiki/Mobile
ProtonMail Openpgp: https://github.com/ProtonMail/crypto/tree/master/openpgp

1. Install Go: brew install go
2. Install Gomobile: go get golang.org/x/mobile/cmd/gomobile
                     //go get -u golang.org/x/mobile/cmd/...
3. Install Gobind: go install golang.org/x/mobile/cmd/gobind
3. Install android sdk and ndk use android studio
4. Set Env: export ANDROID_HOME="/AndroidSDK" #set your own path
5. Init gomobile: gomobile init -ndk /AndroidSDK/ndk-bundle/ #put your own ndk path

6. build examples:
   gomobile build -target=android  #or ios

   bind examples:
   gomobile bind -target ios -o frameworks/name.framework
   gomobile bind -target android

the bind will create framework for ios and jar&aar file for android x86_64 arm arch
   

7. Project uses glide to setup vendor

OTHER NOTES:
two way bridge go & swift:
https://medium.com/@matryer/tutorial-calling-go-code-from-swift-on-ios-and-vice-versa-with-gomobile-7925620c17a4


SOME UNSOLVED ISSUES:
No Mips support but this is fine we don't support it anyway
https://github.com/golang/go/issues/23692   issue with atomic
EXC_BAD_ACCESS is hard to catch
https://github.com/golang/go/issues/21288   memory issue
https://github.com/golang/go/issues/21594   gradle issue
https://github.com/golang/go/issues/23307
https://github.com/golang/go/issues/20241
  upload failed. we are using framework need to confirm this
https://github.com/golang/go/issues/17278   android load jni issue
https://github.com/golang/go/issues/17807   dlopen issue
https://github.com/golang/go/issues/18903   doesn't work well with vender
https://github.com/golang/go/issues/13438   bind issue
https://github.com/golang/go/issues/14332   build types issue
https://github.com/golang/go/issues/15956   no multiple independent bindings support





The build.sh need to modify the path when you use it