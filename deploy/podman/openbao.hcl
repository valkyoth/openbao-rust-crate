ui = true

storage "raft" {
  path = "/openbao/data"
  node_id = "openbao-rust-crate-dev-node1"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/openbao/tls/openbao.crt"
  tls_key_file = "/openbao/tls/openbao.key"
  tls_min_version = "tls13"
}

api_addr = "https://127.0.0.1:9940"
cluster_addr = "https://127.0.0.1:9941"
