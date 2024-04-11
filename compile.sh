#!/bin/sh


echo "[x] Compiling the Encryption utility"
go build -o enc enc.go 


echo "[x] Compiling the Decryption utility"
go build -o dec dec.go 



