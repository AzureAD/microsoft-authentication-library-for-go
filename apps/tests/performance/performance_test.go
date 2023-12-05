// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package performance

import (
	"context"
	"fmt"
	"math/rand"
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
	return base.New("fake_client_id", "https://fake_authority/my_utid", &oauth.Client{
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
	for user := 0; user < users; user++ {
		for token := 0; token < tokens; token++ {
			authParams := client.AuthParams
			authParams.UserAssertion = fmt.Sprintf("fake_access_token%d", user)
			authParams.AuthorizationType = authority.ATOnBehalfOf
			scope := fmt.Sprintf("scope%d", token)

			_, err := client.AuthResultFromToken(context.Background(), authParams, accesstokens.TokenResponse{
				AccessToken:   fmt.Sprintf("fake_access_token%d", user),
				RefreshToken:  "fake_refresh_token",
				ClientInfo:    accesstokens.ClientInfo{UID: "my_uid", UTID: fmt.Sprintf("%dmy_utid", user)},
				ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
				GrantedScopes: accesstokens.Scopes{Slice: []string{scope}},
				IDToken: accesstokens.IDToken{
					RawToken: "x.e30",
				},
			}, true)
			if err != nil {
				panic(err)
			}
		}
	}
}

func queryCache(users int, tokens int, client base.Client) {
	userAssertion := fmt.Sprintf("fake_access_token%d", rand.Intn(users))
	scope := []string{fmt.Sprintf("scope%d", rand.Intn(tokens))}
	params := base.AcquireTokenOnBehalfOfParameters{
		Scopes:        scope,
		UserAssertion: userAssertion,
		Credential:    &accesstokens.Credential{Secret: "fake_secret"},
	}
	_, err := client.AcquireTokenOnBehalfOf(context.Background(), params)
	if err != nil {
		panic(err)
	}
}

func BenchmarkQueryCache(b *testing.B) {
	benchmarks := []struct {
		users, tokens int
	}{
		{1, 10000},
		{1, 100000},
		{10, 10000},
		{100, 10000},
		{1000, 1000},
		{10000, 100},
	}
	for _, bm := range benchmarks {
		b.Run(fmt.Sprintf("%d users %d tokens", bm.users, bm.tokens), func(b *testing.B) {
			client, err := fakeClient()
			if err != nil {
				b.Fatal(err)
			}
			authParams := client.AuthParams
			populateCache(bm.users, bm.tokens, authParams, client)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				queryCache(bm.users, bm.tokens, client)
			}
		})
	}
}
