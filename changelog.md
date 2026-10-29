This library uses GitHub releases to document the changelog. See https://github.com/AzureAD/microsoft-authentication-library-for-go/releases

## Unreleased

OIDC discovery issuer validation now accepts a cross-host regional Microsoft issuer
only when the authority host exactly matches a built-in trusted Microsoft host
(case-insensitively). This expands acceptance for those authorities to HTTPS issuers
with exactly one nonempty label before a built-in trusted host, including arbitrary
region names; no region catalog is consulted. Both URLs must use HTTPS for this
new acceptance rule.

Custom authorities, including CIAM authorities, reject cross-host regional Microsoft
issuers even when instance discovery metadata lists the issuer as an alias.
Built-in Microsoft authorities reject cross-host `ciamlogin.com` issuers even when
listed as aliases. Same-host, other alias, trusted nonregional issuer, and
reverse-direction regional authority behavior is otherwise unchanged. Rejected
metadata is not returned or cached as accepted endpoints. These are issuer-policy
behavior changes, not a claim of a complete credential-theft vulnerability fix.
