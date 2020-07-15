#!/bin/bash
export BIN_FILE=$(echo $1|sed 's/.go/_amd64.bin/g')
export WIN_FILE=$(echo $1|sed 's/.go/_amd64.exe/g')
export MAC_FILE=$(echo $1|sed 's/.go/_amd64_mac.bin/g')
echo go build GOOS=linux GOARCH=amd64 -o artifacts/$BIN_FILE $1
echo go build GOOS=windows GOARCH=amd64 -o artifacts/$WIN_FILE $1
echo go build GOOS=darwin GOARCH=amd64 -o artifacts/$MAC_FILE $1