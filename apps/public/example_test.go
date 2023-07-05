package public_test

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// This example demonstrates the general pattern for authenticating with MSAL Go:
//   - create a client (only necessary at application start--it's best to reuse client instances)
//   - call AcquireTokenSilent() to search for a cached access token
//   - if the cache misses, acquire a new token
func Example() {
	client, err := public.New("client_id", public.WithAuthority("https://login.microsoftonline.com/your_tenant"))
	if err != nil {
		// TODO: handle error
	}

	var result public.AuthResult
	scopes := []string{"scope"}

	// If your application previously authenticated a user, call AcquireTokenSilent with that user's account
	// to use cached authentication data. This example shows choosing an account from the cache, however this
	// isn't always necessary because the AuthResult returned by authentication methods includes user account
	// information.
	accounts, err := client.Accounts(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	if len(accounts) > 0 {
		// There may be more accounts; here we assume the first one is wanted.
		// AcquireTokenSilent returns a non-nil error when it can't provide a token.
		result, err = client.AcquireTokenSilent(context.TODO(), scopes, public.WithSilentAccount(accounts[0]))
	}
	if err != nil || len(accounts) == 0 {
		// cache miss, authenticate a user with another AcquireToken* method
		result, err = client.AcquireTokenInteractive(context.TODO(), scopes)
		if err != nil {
			// TODO: handle error
		}
	}

	// TODO: save the authenticated user's account, use the access token
	_ = result.Account
	_ = result.AccessToken
}
