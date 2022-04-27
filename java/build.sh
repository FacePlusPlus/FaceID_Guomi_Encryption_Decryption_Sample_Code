#/bin/sh

rm -rf bin
mkdir bin
javac -d bin -encoding utf-8  -cp  "libs/*" src/com/megvii/bouncycastle/crypto/engines/*.java

jar cvfm  test.jar mainfest -C bin/ .

