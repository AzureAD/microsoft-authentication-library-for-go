module github.com/AzureAD/microsoft-authentication-library-for-go/attestation

go 1.18

require (
	github.com/AzureAD/microsoft-authentication-library-for-go v1.10.0
	golang.org/x/sys v0.29.0
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
)

// The provider seam is part of the parent change. Dependency modules ignore
// replace directives; this replacement is only for developing both modules in
// this repository before v1.10.0 is released.
replace github.com/AzureAD/microsoft-authentication-library-for-go => ../
