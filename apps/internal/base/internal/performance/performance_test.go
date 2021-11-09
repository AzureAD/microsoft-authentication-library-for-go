// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package performance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

func fakeClient() (base.Client, error) {
	// we use a base.Client so we can provide a fake OAuth client
	return base.New("fake_client_id", "https://fake_authority/fake", &oauth.Client{

		Authority: &fake.Authority{
			InstanceResp: authority.InstanceDiscoveryResponse{
				Metadata: []authority.InstanceDiscoveryMetadata{
					{
						PreferredNetwork: "fake_authority",
						Aliases:          []string{"fake_authority"},
					},
				},
			},
		},
		Resolver: &fake.ResolveEndpoints{
			Endpoints: authority.Endpoints{
				AuthorizationEndpoint: "auth_endpoint",
				TokenEndpoint:         "token_endpoint",
			},
		},
		WSTrust: &fake.WSTrust{},
	})
}

func populateCache(users int, tokens int, authParams authority.AuthParams, client base.Client) {
	tenant := "my_utid"
	for user := 0; user < users; user++ {
		for token := 0; token < tokens; token++ {
			authParams.UserAssertion = fmt.Sprintf("fake_access_token%d", user)
			authParams.AuthorizationType = authority.ATOnBehalfOf
			hID := fmt.Sprintf("%dmy_utid", user)
			authParams.HomeaccountID = hID
			scope := fmt.Sprintf("scope%d", token)
			_, err := client.AuthResultFromToken(context.Background(), authParams, accesstokens.TokenResponse{
				AccessToken:   fmt.Sprintf("fake_access_token%d", user),
				ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
				GrantedScopes: accesstokens.Scopes{Slice: []string{scope}},
				IDToken:       accesstokens.IDToken{TenantID: tenant},
			}, true)
			if err != nil {
				panic(err)
			}
		}
	}
	fmt.Println("Done")
}

func queryCache(users int, tokens int, client base.Client) {
	for user := 0; user < users; user++ {
		for token := 0; token < tokens; token++ {
			userAssertion := fmt.Sprintf("fake_access_token%d", user)
			scope := []string{fmt.Sprintf("scope%d", token)}
			params := base.AcquireTokenOnBehalfOfParameters{
				Scopes:        scope,
				UserAssertion: userAssertion,
				Credential:    &accesstokens.Credential{Secret: "fake_secret"},
			}
			result, err := client.AcquireTokenOnBehalfOf(context.Background(), params)
			if err != nil {
				panic(err)
			}
			if result.AccessToken == "" {
				fmt.Println("Incorrect")
			}
			fmt.Println(result.AccessToken)
		}
	}
}
func TestOnBehalfOfCacheTests(t *testing.T) {
	tests := []struct {
		Users  int
		Tokens int
	}{
		{3, 10000},
		//{1, 100000},
		// {100, 10000},
		// {1000, 10000},
		// {10000, 100},
	}

	for _, test := range tests {
		client, err := fakeClient()
		if err != nil {
			panic(err)
		}
		authParams := client.AuthParams
		populateCache(test.Users, test.Tokens, authParams, client)
		queryCache(test.Users, test.Tokens, client)
	}
}
