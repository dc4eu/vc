#!/usr/bin/env bash

######################
# Issuer
######################

# isser: generate a private key for a curve
openssl ecparam -name prime256v1 -genkey -noout -out private_ec256.pem

# isser: generate corresponding public key
openssl ec -in private_ec256.pem -pubout -out public_ec256.pem

######################
# Verifier
######################
#SUBJECT="/CN=vcverifier.sunet.se"
#SAN_DNS="vcverifier.sunet.se"
#DAYS_VALID=365
#
## out files
#PRIVATE_KEY="private_verifier_ec256.pem"
#PUBLIC_KEY="public_verifier_ec256.pem"
#CERT_PEM="verifier_x509_cert.pem"
#CSR_FILE="verifier_x509.csr"
#EXT_FILE="verifier_x509_cert_ext.cnf"
#
#openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY"
##echo "Created: $PRIVATE_KEY"
#
#openssl ec -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
##echo "Created: $PUBLIC_KEY"
#
## ---------------------------------------------
## Certificate Signing Request (CSR)
## ---------------------------------------------
#openssl req -new -key "$PRIVATE_KEY" -subj "$SUBJECT" -out "$CSR_FILE"
#
## ---------------------------------------------
## Ext for SAN (SubjectAltName)
## ---------------------------------------------
#cat > "$EXT_FILE" <<EOF
#subjectAltName=DNS:$SAN_DNS
#EOF
#
## ---------------------------------------------
## Self-signed cert med SAN (x5c-style)
## ---------------------------------------------
#openssl x509 -req \
#    -in "$CSR_FILE" \
#    -signkey "$PRIVATE_KEY" \
#    -out "$CERT_PEM" \
#    -days "$DAYS_VALID" \
#    -extfile "$EXT_FILE"
#
##echo "Created: $CERT_PEM"