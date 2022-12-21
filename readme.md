This repository contains a Traefik plugin to forward a mTLS client             
certificate via HTTP Headers
                                                           
[![Build
Status](https://github.com/pvliesdonk/mtlsforward/workflows/Main/badge.svg?branch=master)](https://github.com/pvliesdonk/mtlsforward/actions)
                                                           
The existing plugins can be browsed into the [Plugin Catalog](https://plugins.traefik.io).
                                                           
# Configuration

## Static Configuration
Add the following to the static configuration traefik.yaml

```yaml
experimental:
  plugins:
    mtlsforward:
      moduleName: "github.com/pvliesdonk/mtlsforward"
      version: "v0.1.0"         # check latest version
```
## Dynamic Configuration
Then define the following middleware in the dynamic configuration:

```yaml
# this plugin makes no sense without client authentication.
tls:
  options:
    mtls_any:
      clientAuth:  
        clientAuthType: RequestClientCert         # any certificate is okay

http:
  middlewares:
    mlts-forward:
      plugin:
        mtlsforward:
          headers:
            sslClientCert: "SSL_CLIENT_CERT"      
            sslCertChainPrefix: "SSL_CERT_CHAIN" 
          encodePem: false   #optional, encode certificates as PEM
          encodeUrl: false   #optional, enable URL encoding
          removeNewline: true #remove newlines from PEM encoding          
          
  routers:
    my-router:
      rule: Host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - websecure
      middlewares:
        - mtls-forward                            # require mTLS on this router
      tls:
        options: mtls_any                       

  services:
    service-foo:
      loadBalancer: http://127.0.0.1:5000 
```

# Settings for the plugin:

| Option                       | Description                     |
|------------------------------|---------------------------------|  
| `headers.sslClientCert`      | Name of the header in which to put the found client certificate. A commonly used name is `SSL_CLIENT_CERT` |
| `headers.sslCertChainPrefix` | The plugin will create additional headers for every certificate in the chain provided. A commonly used name is `SSL_CERT_CHAIN`, which results in values `SSL_CERT_CHAIN_0, `SSL_CERT_CHAIN_1`, etc. |
| `encodePem`	               | Provide a PEM encoding of the certificates. If false, only a base64 encoded certificate will be provided |
| `encodeUrl`		       | Provide additional URL encoding of the certificates |
| `removeNewline`      | Remove newlines from PEM encoding |

# Kubernetes / Helm

Add the following to the helm charts `values.yaml`
```yaml
experimental:
  plugins:
    enabled: true
    mtlsforward:
      moduleName: "github.com/pvliesdonk/mtlsforward"
      version: "v0.0.5"
```

And use the following CRDs to configure:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: TLSOption
metadata:
  name: mtls-any
spec:
  clientAuth:
    clientAuthType: RequestClientCert
---
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: mtls-forward
spec:
  plugin:
    mtlsforward:
      headers:
        sslClientCert: "SSL_CLIENT_CERT"      #
        sslCertChainPrefix: "SSL_CERT_CHAIN"  #
      encodePem: true
      encodeUrl: false
      removeNewline: true
```

and enable the following annotations to you ingress
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.middlewares: mtls-forward@kubernetescrd
    traefik.ingress.kubernetes.io/router.tls: true
    traefik.ingress.kubernetes.io/router.tls.options: traefik-mtls-any@kubernetescrd  # name is not the same as above!
```
