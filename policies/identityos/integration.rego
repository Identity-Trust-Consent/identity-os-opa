package identityos.integration

default allow = false

allow {
  input.active == true
  input.tenantMatches == true
  input.ownerMatches == true
  input.roleAllowed == true
  input.scopeAllowed == true
  input.consentValid == true
  input.trustScore >= input.minimumTrust
}

decision := {"allow": allow, "version": "identityos.integration.v1"}
