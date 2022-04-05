# Routing using `x-forwarded-client-cert`

This is an interesting use-case, where we have a "gateway" that routes requests based on the
extracted [`x-forwarded-client-cert`](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert).

Suppose we have four clients, each of them has a certificate pair (`api-client.customer0{1..4}.com.{crt,key}`).

Each client connects to gateway, and terminated (validated via mTLS, with provided validation contexts: trusted CA and hash).

```yaml
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              require_client_certificate: true
              common_tls_context:
                validation_context:
                  trusted_ca:
                    filename: ca.crt
                  verify_certificate_hash:
                    - 94b0743a0159e4003ed1d84303bda2db53693f3b635c4a23447f9df6657444ac
                    - 7f874453537499e6816a1b3ea5dbbfc5728ccadcd1c18717b16ea3783e3c0936
                    - 00e018b8b62ff971dd9668ef3828aac05dd12f2d6f1e6e617f7e18c46b009564
                    - 3780d91ade6940c5780df86df330bafb6d7884fe9173988021fffda6f8d9487c
                tls_certificates:
                  - certificate_chain:
                      filename: example.com.crt
                    private_key:
                      filename: example.com.key

```

The extracted hash and SAN then being used as the routing cue, for example for `customer01`:

```yaml
                      routes:
                        - match:
                            prefix: "/"
                            headers:
                              - name: x-forwarded-client-cert
                                exact_match: Hash=94b0743a0159e4003ed1d84303bda2db53693f3b635c4a23447f9df6657444ac;DNS=api-client.customer01.com
                          route:
                            cluster: customer01
```

The "upstream" cluster is a "forward-proxy" which has `customer01`'s "trusted" (internal) client
certificate-pair (`customer0{1..4}.example.com.{crt,key}`)

```yaml
    - name: customer01
      connect_timeout: 1s
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.dynamic_forward_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
          dns_cache_config:
            name: dynamic_forward_proxy_cache_config
            dns_lookup_family: V4_ONLY
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          common_tls_context:
            validation_context:
              trusted_ca:
                filename: ca.crt
            tls_certificates:
              - certificate_chain:
                  filename: customer01.example.com.crt
                private_key:
                  filename: customer01.example.com.key
```

This cluster connects to the "back"-proxy which validates the attached certificate chain, here
we simply check if the cert is signed by a trusted CA.

```yaml

          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              require_client_certificate: true
              common_tls_context:
                validation_context:
                  trusted_ca:
                    filename: ca.crt
                tls_certificates:
                  - certificate_chain:
                      filename: hello.com.crt
                    private_key:
                      filename: hello.com.key
```

## Running the demo

> Since I'm lazy, I registered the following to my `/etc/hosts`

```
127.0.0.1 example.com
127.0.0.1 hello.com
```

Run the "front" proxy:

```
$  ~/.func-e/versions/1.21.0/bin/envoy -c front.yaml --use-dynamic-base-id
```

> Yes, you can download the `envoy` binary from https://func-e.io/.

Also, in another terminal session, run the "back" proxy:

```console
$  ~/.func-e/versions/1.21.0/bin/envoy -c back.yaml --use-dynamic-base-id
```

Afterward, acts as a client, e.g. `customer01`:

```console
$ curl https://example.com:10000/app1 --cacert ca.crt --cert api-client.customer01.com.crt --key api-client.customer01.com.key -v
...
< HTTP/1.1 200 OK
< date: Tue, 05 Apr 2022 09:20:08 GMT
< content-type: application/json
< content-length: 624
< server: envoy
< access-control-allow-origin: *
< access-control-allow-credentials: true
< x-envoy-upstream-service-time: 870
<
{
  "args": {},
  "data": "",
  "files": {},
  "form": {},
  "headers": {
    "Accept": "*/*",
    "Host": "hello.com",
    "User-Agent": "curl/7.68.0",
    "X-Amzn-Trace-Id": "Root=1-624c09c8-2f70673a5168644b64c114cb",
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000",
    "X-Forwarded-Client-Cert": "Hash=94b0743a0159e4003ed1d84303bda2db53693f3b635c4a23447f9df6657444ac;DNS=api-client.customer01.com,Hash=6659134bcf5b206e7f10660dd5e8531fb67b4327a6aa18c18c2aacbc230ddaaf;DNS=customer01.example.com"
  },
  "json": null,
  "method": "GET",
  "origin": "34.124.236.29",
  "url": "https://hello.com/anything/app1"
```

And as `customer02`:

```
$ curl https://example.com:10000/app1 --cacert ca.crt --cert api-client.customer02.com.crt --key api-client.customer02.com.key -v
< HTTP/1.1 200 OK
< date: Tue, 05 Apr 2022 09:21:10 GMT
< content-type: application/json
< content-length: 624
< server: envoy
< access-control-allow-origin: *
< access-control-allow-credentials: true
< x-envoy-upstream-service-time: 220
<
{
  "args": {},
  "data": "",
  "files": {},
  "form": {},
  "headers": {
    "Accept": "*/*",
    "Host": "hello.com",
    "User-Agent": "curl/7.68.0",
    "X-Amzn-Trace-Id": "Root=1-624c0a06-6e9895c61b7f9cb113aa4ad1",
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000",
    "X-Forwarded-Client-Cert": "Hash=7f874453537499e6816a1b3ea5dbbfc5728ccadcd1c18717b16ea3783e3c0936;DNS=api-client.customer02.com,Hash=00e0d25f8b65c9185457a8f0ad8d083450a079c2ef9f20f24ff6f11dfd48b915;DNS=customer02.example.com"
  },
  "json": null,
  "method": "GET",
  "origin": "34.124.236.29",
  "url": "https://hello.com/anything/app1"
}
```

Accessing `/app2` also can be done:

```
$ curl https://example.com:10000/app2 --cacert ca.crt --cert api-client.customer01.com.crt --key api-client.customer01.com.key -v
< HTTP/1.1 200 OK
< date: Tue, 05 Apr 2022 09:21:57 GMT
< content-type: application/json
< content-length: 624
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
    "Host": "hello.com",
    "User-Agent": "curl/7.68.0",
    "X-Amzn-Trace-Id": "Root=1-624c0a35-47564d9b186df9ed0d866de7",
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000",
    "X-Forwarded-Client-Cert": "Hash=94b0743a0159e4003ed1d84303bda2db53693f3b635c4a23447f9df6657444ac;DNS=api-client.customer01.com,Hash=6659134bcf5b206e7f10660dd5e8531fb67b4327a6aa18c18c2aacbc230ddaaf;DNS=customer01.example.com"
  },
  "json": null,
  "method": "GET",
  "origin": "34.124.236.29",
  "url": "https://hello.com/anything/app2"
}
```

## The little Lua script

Yes, there is this little Lua script that transform the `:authority`, from `example.com:10000` to
`hello.com:10001`. We forward the `:path` header but before that, we prepend that with `/anything`
prefix when "forwarding" the request from the "front" to the "back".

## Inspecting the certificate

You can use [`step`](https://smallstep.com/docs/step-cli) CLI to inspect the certificates.

```console
$ step certificate inspect app1.example.com.crt
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

Or, you can surely do it in Go:

```console
$ go run hash.go app1.example.com.crt
13ee0d38e5517a257b9f2e9f38b0c9543f8312a8f40c32b5ad3358c9f1a6c9b3
```

## Creating the certificates

Since I'm a big fan of `step`, these certificates are generated using the `step` CLI.

See: https://smallstep.com/docs/step-cli/basic-crypto-operations#create-and-work-with-x509-certificates.

> Note: You might want to "bundle" (concatenate) the root and intermediate CA certificates.

Also see: https://smallstep.com/docs/step-cli/reference/crypto/change-pass to remove the password
from a key (yes, it involves `--insecure` and `--no-password` flags).
