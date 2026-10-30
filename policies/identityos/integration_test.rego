package identityos.integration

test_deny_missing {
  not allow with input as {}
}
test_allow_complete {
  allow with input as {"active":true,"tenantMatches":true,"ownerMatches":true,
    "roleAllowed":true,"scopeAllowed":true,"consentValid":true,"trustScore":80,"minimumTrust":60}
}
test_deny_consent {
  not allow with input as {"active":true,"tenantMatches":true,"ownerMatches":true,
    "roleAllowed":true,"scopeAllowed":true,"consentValid":false,"trustScore":80,"minimumTrust":60}
}
test_deny_trust {
  not allow with input as {"active":true,"tenantMatches":true,"ownerMatches":true,
    "roleAllowed":true,"scopeAllowed":true,"consentValid":true,"trustScore":40,"minimumTrust":60}
}
