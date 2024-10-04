# Overview

Simple tls microservice

## Clone this repo

```
git clone https://github.com/lmzuccarelli/rust-hypertls-microservice

cd rust-hypertls-microservice
```

## TLS cert creation

create a CA authority (self signed)

```
openssl genrsa -out certs/rootCA.key 2048
```

generate root certs

```
openssl req -x509 -new -nodes -key certs/rootCA.key -sha256 -days 1024 -out certs/rootCA.pem -subj "/C=IT/ST=ANCONA/L=ANCONA/O=QUAY/OU=IT Dev/CN=mostro"
```

generate server key

```
openssl genrsa -out certs/ssl.key 2048
```

create a signing request with subject 

```
openssl req -new -key certs/ssl.key -out certs/ssl.csr -subj "/C=IT/ST=ANCONA/L=ANCONA/O=QUAY/OU=IT Dev/CN=mostro"
```

use openssl config to generate ssl cert 

```
openssl x509 -req -in certs/ssl.csr -CA certs/rootCA.pem -CAkey certs/rootCA.key -CAcreateserial -out certs/ssl.cert -days 356 -extensions v3_req -extfile certs/openssl.conf -passin pass:""
```

copy rootCA to system wide trust store

```
sudo cp certs/rootCA.pem /etc/pki/ca-trust/source/anchors/rootCA.pem
```

update trusted store

```
sudo update-ca-trust extract
```
