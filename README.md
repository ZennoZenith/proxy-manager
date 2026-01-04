## Tools required

- make
- cmake

## Generating Self Signed TLS Certificate

### Does not include Subject Alternative Names (SAN)

`example.com.key` → private key

`example.com.crt` → self-signed certificate

Valid for 365 days

```sh
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout example.com.key \
  -out example.com.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=example.com"
```

## includes SAN

Create `openssl.cnf`
 |
 V

```cnf
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
CN = example.com

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = example.com
DNS.2 = www.example.com
```


```sh
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout example.com.key \
  -out example.com.crt \
  -config openssl.cnf
```

Verify certificate

```sh
openssl x509 -in example.com.crt -text -noout
```

Example usage in nginx config

```nginx
ssl_certificate     /path/to/example.com.crt;
ssl_certificate_key /path/to/example.com.key;
```

