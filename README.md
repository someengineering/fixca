# `fixca` - FIX Internal Certificate Authority

## Introduction

FIX CA is the internal Certificate Authority for [FIX](https://fix.tt/). It provides the same interface as [Resoto Core's](https://github.com/someengineering/resoto/tree/main/resotocore) built-in CA and is used to issue certificates for FIX internal services.

FIX CA stores its CA cert and key in a K8s secret. As such it needs to either run inside a K8s cluster with appropriate permissions or have access to a K8s cluster via `KUBECONFIG`.

The API is fully compatible with Resoto Core's CA API. I.e. `/ca/cert` to download the CA cert and `/ca/sign` to sign a CSR. Other than Resoto Core JWT authentication can not be turned off and a pre-shared-key is mandatory to sign a CSR.

## Usage

```bash
usage: fixca [-h] --psk PSK [--port PORT] [--namespace NAMESPACE] [--secret SECRET] [--verbose | --trace | --quiet]

FIX Certification Authority

options:
  -h, --help            show this help message and exit
  --psk PSK             Pre-shared-key
  --port PORT           HTTPS port to listen on (default: 7900)
  --namespace NAMESPACE
                        K8s namespace (default: fix)
  --secret SECRET       Secret name (default: fix-ca)
  --verbose, -v         Verbose logging
  --trace               Trage logging
  --quiet               Only log errors
```
