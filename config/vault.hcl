
    listener "tcp" {
      address       = "0.0.0.0:8200"
      tls_cert_file = "/vault/certs/vault.crt"
      tls_key_file  = "/vault/certs/vault.key"
      tls_client_ca_file = "/vault/certs/ca.crt"
      tls_require_and_verify_client_cert = "true"
    }
    storage "inmem" {}
    disable_mlock = true
    ui = true
    