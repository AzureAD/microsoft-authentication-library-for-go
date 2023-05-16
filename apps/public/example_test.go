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

	var userAccount public.Account
	accounts, err := client.Accounts(context.TODO())
	if err != nil {
		// TODO: handle error
	}
	if len(accounts) > 0 {
		// there may be more accounts; here we assume the first one is wanted
		userAccount = accounts[0]
	}
	scopes := []string{"scope"}
	result, err := client.AcquireTokenSilent(context.TODO(), scopes, public.WithSilentAccount(userAccount))
	if err != nil {
		// cache miss, authenticate a user with another AcquireToken* method
		result, err = client.AcquireTokenInteractive(context.TODO(), scopes)
		if err != nil {
			// TODO: handle error
		}
	}
	if err == nil {
		// this account can be used in a future AcquireTokenSilent call
		userAccount = result.Account
		// TODO: use access token
		_ = result.AccessToken
	}
}
