path "fixture-kv/data/record" {
  capabilities = ["read", "update"]
  control_group = {
    ttl = "300s"
    self_auth_allowed = false
    factor "operators" {
      controlled_capabilities = ["read", "update"]
      identity {
        group_names = ["operators"]
        approvals = 2
      }
    }
    factor "security" {
      controlled_capabilities = ["read", "update"]
      identity {
        group_names = ["security"]
        approvals = 1
      }
    }
  }
}
