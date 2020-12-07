package integrationtests

// Scopes.
const (
	MsIDlabDefaultScope = "https://msidlab.com/.default"
	GraphDefaultScope   = "https://graph.windows.net/.default"
)

// MicrosoftAuthorityHost is the host authority for Microsoft.
const MicrosoftAuthorityHost = "https://login.microsoftonline.com/"

// Authority values.
const (
	OrganizationsAuthority = MicrosoftAuthorityHost + "organizations/"
	CommonAuthority        = MicrosoftAuthorityHost + "common/"
	MicrosoftAuthority     = MicrosoftAuthorityHost + "microsoft.onmicrosoft.com"
	MsIDlabTenantAuthority = MicrosoftAuthorityHost + "msidlab4.onmicrosoft.com"
)
