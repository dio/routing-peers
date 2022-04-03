# Routing using `x-forwarded-client-cert`

This is an interesting use-case, where we have a "gateway" that routes requests based on the
extracted [`x-forwarded-client-cert`](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert).

Suppose we have `example.com` hosting our `gateway`, and we have `app1.example.com` and
`app2.example.com` as the clients. Each client has its certificate pair, annotated with its `DNS`,
encoded as the certificate's `SAN`.

As an example, the following is the SAN of `app1.example.com` client certificate.

```
            X509v3 Subject Alternative Name:
                DNS:app1.example.com
```

And make sure you have "Client Authentication" as one of its key usages:

```
            X509v3 Extended Key Usage:
                Server Authentication, Client Authentication
```

The route matching entry for `app1.example.com` is done as the following:

```yaml
                        - match:
                            prefix: "/"
                            headers:
                              - name: x-forwarded-client-cert
                                exact_match: Hash=13ee0d38e5517a257b9f2e9f38b0c9543f8312a8f40c32b5ad3358c9f1a6c9b3;DNS=app1.example.com
                          route:
                            prefix_rewrite: "/anything/app1"
                            host_rewrite_literal: httpbin.org
                            cluster: service_httpbin
```

With the given ['config.yaml'](./config.yaml),

> Note: Since I'm lazy, you need to add: `127.0.0.1 example.com` entry to your `/etc/hosts` to make the DNS resolution works.

```console
$ pwd
path/to/this/repository
$ ~/.func-e/versions/1.21.0/bin/envoy -c config.yaml
```

> Yes, you can install the `envoy` binary using [func-e](https://func-e.io/).

And in another tab, by using the `app1.example.com` client certificate:

```
$ curl https://example.com:10000 --cacert ca.crt --cert app1.example.com.crt --key app1.example.com.key -v
< HTTP/1.1 200 OK
< date: Sun, 03 Apr 2022 08:02:26 GMT
< content-type: application/json
< content-length: 557
< server: envoy
< access-control-allow-origin: *
< access-control-allow-credentials: true
< x-envoy-upstream-service-time: 651
<
{
  "args": {},
  "data": "",
  "files": {},
  "form": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.68.0",
    "X-Amzn-Trace-Id": "Root=1-62495492-12e48455193e572b4a20df77",
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000",
    "X-Envoy-Original-Path": "/",
    "X-Forwarded-Client-Cert": "Hash=13ee0d38e5517a257b9f2e9f38b0c9543f8312a8f40c32b5ad3358c9f1a6c9b3;DNS=app1.example.com"
  },
  "json": null,
  "method": "GET",
  "origin": "34.124.236.29",
  "url": "https://httpbin.org/anything/app1"
}
```

See that the `gateway` rewrites the path to: `/anything/app1` (that's expected!).

Let's try with the `app2.example.com` client certificate:

```console
$ curl https://example.com:10000 --cacert ca.crt --cert app2.example.com.crt --key app2.example.com.key -v
< HTTP/1.1 200 OK
< date: Sun, 03 Apr 2022 08:03:38 GMT
< content-type: application/json
< content-length: 557
< server: envoy
< access-control-allow-origin: *
< access-control-allow-credentials: true
< x-envoy-upstream-service-time: 857
<
{
  "args": {},
  "data": "",
  "files": {},
  "form": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.68.0",
    "X-Amzn-Trace-Id": "Root=1-624954da-49737bf4255cec9741a051f5",
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000",
    "X-Envoy-Original-Path": "/",
    "X-Forwarded-Client-Cert": "Hash=4c293ae780318973ff6220ce2beffbbc006225fa96a837483c9f20afbac61263;DNS=app2.example.com"
  },
  "json": null,
  "method": "GET",
  "origin": "34.124.236.29",
  "url": "https://httpbin.org/anything/app2"
}
```

Yes, now it is `anything/app2`!

## Inspecting the certificate

You can use [`step`](https://smallstep.com/docs/step-cli) CLI to inspect the certificates.

```console
$ step inspect app1.example.com.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 37659966509261525488541052008780650889 (0x1c550bb4566174bec6c2da8a0621d989)
    Signature Algorithm: ECDSA-SHA256
        Issuer: CN=Example Intermediate CA 1
        Validity
            Not Before: Apr 3 07:16:57 2022 UTC
            Not After : Apr 3 07:16:53 2023 UTC
        Subject: CN=app1.example.com
        Subject Public Key Info:
            Public Key Algorithm: ECDSA
                Public-Key: (256 bit)
                X:
                    3b:fe:f0:4b:f4:dd:cf:1d:ec:cb:ea:00:31:08:f3:
                    64:cd:a5:d7:5d:78:6b:67:3f:3e:58:76:58:06:7b:
                    02:b4
                Y:
                    59:d9:f5:b3:e2:40:e1:24:95:c5:07:3f:48:d3:df:
                    ec:e8:d2:fb:2f:7c:7b:24:10:69:55:57:48:86:dd:
                    5b:b2
                Curve: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                Server Authentication, Client Authentication
            X509v3 Subject Key Identifier:
                50:92:E5:79:12:E4:E5:07:96:F6:6D:31:34:36:74:B8:E7:4A:37:7F
            X509v3 Authority Key Identifier:
                keyid:D8:BC:F0:E6:C3:C9:BF:33:44:D4:DE:25:2C:78:44:9D:03:1E:8C:0B
            X509v3 Subject Alternative Name:
                DNS:app1.example.com
    Signature Algorithm: ECDSA-SHA256
         30:45:02:20:2d:c5:d1:8b:8b:3d:c5:34:65:a4:c4:37:c7:cf:
         2f:54:a7:0e:8e:f1:51:e5:e2:54:b0:b8:5a:42:01:f5:0e:bf:
         02:21:00:c8:e0:93:a5:c6:b8:6a:72:26:36:a7:d7:86:5d:ae:
         7e:e7:99:6c:7d:32:0b:dc:72:b6:48:8d:66:db:d0:1e:72
```

## Getting the "hash" value of a peer certificate

Envoy generates this SHA-256 hash in hex representation when receiving the request with peer
certificate. The reference implementation when using node is shown in [hash.js](./hash.js).

> Note: tested using node-16.

```console
$ yarn # or npm install
$ ./hash.js app1.example.com.crt
13ee0d38e5517a257b9f2e9f38b0c9543f8312a8f40c32b5ad3358c9f1a6c9b3
```

## Creating the certificates

Since I'm a big fan of `step`, these certificates are generated using the `step` CLI.

See: https://smallstep.com/docs/step-cli/basic-crypto-operations#create-and-work-with-x509-certificates.

> Note: You might want to "bundle" (concatenate) the root and intermediate CA certificates.

Also see: https://smallstep.com/docs/step-cli/reference/crypto/change-pass to remove the password
from a key (yes, it involves `--insecure` and `--no-password` flags).
