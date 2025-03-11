#!/usr/bin/env bash

# isser: generate a private key for a curve
openssl ecparam -name prime256v1 -genkey -noout -out private_ec256.pem

# isser: generate corresponding public key
openssl ec -in private_ec256.pem -pubout -out public_ec256.pem


# verifier: generate a private key for a curve
openssl ecparam -name prime256v1 -genkey -noout -out private_verifier_ec256.pem

# verifier: generate corresponding public key
openssl ec -in private_verifier_ec256.pem -pubout -out public_verifier_ec256.pem
