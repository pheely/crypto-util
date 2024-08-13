# README

## RSA Keys

### Create a RSA Key and a CSR

OpenSSL:
```bash
openssl req -new -sha256 -nodes -out csr.csr -newkey rsa:2048 \
-keyout privatekey.key -days 365 -config san.conf
```

This will generate a PKCS#8 2048-bit RSA key and a certificate signing request.

### Convert a PKCS#8 RSA Key to PKCS#1 or vice versa

PKCS#8 keys' header and footer:
```text
-----BEGIN PRIVATE KEY-----

-----END PRIVATE KEY-----
```

PKCS#1 keys' header and footer:
```text
-----BEGIN RSA PRIVATE KEY-----

-----END RSA PRIVATE KEY-----
```

From pkcs#8 to pkcs#1:
```bash
openssl pkey -in pkcs8.pem -traditional -out pkcs1.pem
```

From pkcs#1 to pkcs#8
```bash
openssl pkey -in pkcs1.pem -out pkcs8.pem
```

### Get Public Key from Private Key

```bash
openssl pkey -in privatekey.pem -pubout -out publickey.pem
```