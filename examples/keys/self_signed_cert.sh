#!/usr/bin/env bash

echo "
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req

[ dn ]
C  = US
ST = State
L  = City
O  = Organization
OU = IT
CN = $1

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $1
" > openssl.cnf

mkdir -p $1

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "$1/key.pem" \
  -out "$1/server.crt" \
  -config openssl.cnf
