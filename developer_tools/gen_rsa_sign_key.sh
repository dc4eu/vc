#!/usr/bin/env bash

# generate a private key for RSA
openssl genrsa -out private_rsa.pem 2048

# generate corresponding public key
openssl rsa -in private_rsa.pem -pubout -out public_rsa.pem