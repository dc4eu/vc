#!/usr/bin/env bash

######################
# Issuer
######################

# generate a private key for RSA
#//TODO: masv: rename here and used places to private_isser_rsa.pem?
openssl genrsa -out private_rsa.pem 2048

# generate corresponding public key
#//TODO: masv: rename here and used places to public_isser_rsa.pem?
openssl rsa -in private_rsa.pem -pubout -out public_rsa.pem

######################
# Verifier
######################

# ---------------------------------------------
# Configuration
# ---------------------------------------------
SUBJECT="/CN=vcverifier.sunet.se"
SAN_DNS="vcverifier.sunet.se"
DAYS_VALID=90

# Output file names
PRIVATE_KEY="private_verifier_rsa.pem"
PUBLIC_KEY="public_verifier_rsa.pem"
CERT_PEM="verifier_x509_cert.pem"
CSR_FILE="verifier_x509.csr"
EXT_FILE="verifier_x509_cert_ext.cnf"

# ---------------------------------------------
# Generate RSA key pair
# ---------------------------------------------
openssl genrsa -out "$PRIVATE_KEY" 2048
#echo "Created: $PRIVATE_KEY"

openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
#echo "Created: $PUBLIC_KEY"

# ---------------------------------------------
# Create Certificate Signing Request (CSR)
# ---------------------------------------------
openssl req -new -key "$PRIVATE_KEY" -subj "$SUBJECT" -out "$CSR_FILE"

# ---------------------------------------------
# Subject Alternative Name (SAN) extension
# ---------------------------------------------
cat > "$EXT_FILE" <<EOF
subjectAltName=DNS:$SAN_DNS
EOF

# ---------------------------------------------
# Generate self-signed certificate with SAN
# ---------------------------------------------
openssl x509 -req \
    -in "$CSR_FILE" \
    -signkey "$PRIVATE_KEY" \
    -out "$CERT_PEM" \
    -days "$DAYS_VALID" \
    -extfile "$EXT_FILE"
