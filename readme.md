This repository contains a Traefik plugin to forward a mTLS client             
certificate via HTTP Headers
                                                           
[![Build
Status](https://github.com/pvliesdonk/mtlsforward/workflows/Main/badge.svg?branch=master)](https://github.com/pvliesdonk/mtlsforward/actions)
                                                           
The existing plugins can be browsed into the [Plugin Catalog](https://plugins.traefik.io).
                                                           
## Configuration
                   
Add the following to the static configuration

```yaml
# Static configuration

experimental:
  plugins:
    mtlsforward:
      moduleName: "github.com/pvliesdonk/mtlsforward"
      version: "V0.1.0"         # check latest version
```

Then define the following middleware in the dynamic configuration:

```yaml
# Dynamic configuration

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

Settings for the plugin:

+------------------------------+---------------------------------+
| Option                       | Description                     |
+------------------------------+---------------------------------+  
| `headers.sslClientCert`      | Name of the header in which to put the found client certificate. A commonly used name is `SSL_CLIENT_CERT` |
| `headers.sslCertChainPrefix` | The plugin will create additional headers for every certificate in the chain provided. A commonly used name is `SSL_CERT_CHAIN`, which results in values `SSL_CERT_CHAIN_0, `SSL_CERT_CHAIN_1`, etc. |
| `encodePem`	               | Provide a PEM encoding of the certificates. If false, only a base64 encoded certificate will be provided |
| `encodeUrl`		       | Provide additional URL encoding of the certificates |
+------------------------------+---------------------------------+