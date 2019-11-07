package msalgo

// AuthenticationResult contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication. For details see https://aka.ms/msal-net-authenticationresult
type IAuthenticationResult interface {
	GetAccessToken() string
}
