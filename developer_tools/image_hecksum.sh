#!/usr/bin/env bash

checksum=$(openssl dgst -sha256 -binary $1 | openssl base64 -A)

printf "\nbase64 encoded checksum: %s\n\n" "$checksum"