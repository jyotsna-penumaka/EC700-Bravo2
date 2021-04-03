#!/bin/bash

# REFERENCE : https://www.embedded.com/using-digital-signatures-for-data-integrity-checking-in-linux/ 

#install opkg on openWRT
opkg update
opkg install libopenssl
opkg install openssl-util

#generates the private and public cert:
openssl req -nodes -x509 -sha256 -newkey rsa:4096 -keyout "$HOME/.ssh/priv.key" -out "$HOME/.ssh/pub.crt" -days 365 -subj "/C=US/ST=Mass/L=Boston/O=BostonUniversity/OU=DEV/CN=www.bu.edu"

# needed when you want to resign a file
objcopy --remove-section=.sig a.o

# truncate the files
dd bs=512 seek=1 of=nullbytes count=0 if=dummy.txt of=dummy.txt

# add the 512 null bytes to the ELF header
objcopy --add-section .sig=dummy.txt --set-section-flags .sig=noload,readonly a.o

# save the md5 hash of the file
md5sum a.o | awk '{ print $1 }' > "$HOME/.ssh/md5sum_hash"

# sign the binary
openssl dgst -sha256 -sign "$HOME/.ssh/priv.key" -out "$HOME/.ssh/bin_signature" "$HOME/.ssh/md5sum_hash"

# verify the signature 
openssl dgst -sha256 -verify <(openssl x509 -in "$HOME/.ssh/pub.crt" -pubkey -noout) -signature "$HOME/.ssh/bin_signature" "$HOME/.ssh/md5sum_hash"

# add the signature to the elf header
objcopy --update-section .sig="$HOME/.ssh/bin_signature" --set-section-flags .sig=noload,readonly a.o

# check the signature
objdump -sj .sig a.o