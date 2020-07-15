#!/bin/bash
echo Building
BIN_FILE=$(echo $1|sed 's/.go/_amd64\.bin/g'|sed 's/\///g'|sed 's/\.//g')
WIN_FILE=$(echo $1|sed 's/.go/_amd64\.exe/g'|sed 's/\///g'|sed 's/\.//g')
MAC_FILE=$(echo $1|sed 's/.go/_amd64_mac\.bin/g'|sed 's/\///g'|sed 's/\.//g')
echo go build GOOS=linux GOARCH=amd64 -o artifacts/$BIN_FILE $1
go build GOOS=linux GOARCH=amd64 -o artifacts/$BIN_FILE $1
go build GOOS=windows GOARCH=amd64 -o artifacts/$WIN_FILE $1
go build GOOS=darwin GOARCH=amd64 -o artifacts/$MAC_FILE $1
ls -la artifacts
