# `fixca` - FIX Internal Certificate Authority

## Introduction

FIX CA is the internal Certificate Authority for [FIX](https://fix.tt/). It is based on [Resoto Core's](https://github.com/someengineering/resoto/tree/main/resotocore) built-in CA and used to sign certificates for FIX internal services.

FIX CA stores its CA cert and key in a K8s secret.

The API is fully compatible with Resoto Core's CA API. I.e. `/ca/cert` to download the CA cert and `/ca/sign` to sign a CSR. Other than Resoto Core JWT authentication can not be turned off and a pre-shared-key is mandatory to sign a CSR.

## Usage

```bash
usage: fixca [-h] --psk PSK [--port PORT] [--verbose | --trace | --quiet]

FIX Certification Authority

options:
  -h, --help     show this help message and exit
  --psk PSK      Pre-shared-key
  --port PORT    TCP port to listen on
  --verbose, -v  Verbose logging
  --trace        Trage logging
  --quiet        Only log errors
```
