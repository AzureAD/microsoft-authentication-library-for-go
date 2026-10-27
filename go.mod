module github.com/AzureAD/microsoft-authentication-library-for-go

go 1.25.0

// v1.10.0 was re-tagged after publication; use v1.10.1.
retract v1.10.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/google/uuid v1.3.0
	github.com/kylelemons/godebug v1.1.0
	github.com/montanaflynn/stats v0.7.0
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8
	golang.org/x/net v0.55.0
	golang.org/x/sync v0.20.0
)

require (
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)
