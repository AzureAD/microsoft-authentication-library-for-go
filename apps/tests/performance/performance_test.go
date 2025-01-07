// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package performance

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/montanaflynn/stats"
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
func calculateStats(users, tokens int, duration []float64) {

	fmt.Printf("No of users: %d, No of tokens per user: %d \n", users, tokens)

	mean, err := stats.Mean(duration)
	if err != nil {
		panic(err)
	}
	meanTime := mean / float64(time.Microsecond)
	fmt.Println("Mean")
	fmt.Println(meanTime)

	median, err := stats.Median(duration)
	medianTime := median / float64(time.Microsecond)
	if err != nil {
		panic(err)
	}
	fmt.Println("Median")
	fmt.Println(medianTime)

	stdDev, err := stats.StandardDeviation(duration)
	stdDevTime := stdDev / float64(time.Microsecond)
	if err != nil {
		panic(err)
	}
	fmt.Println("Standard Deviation")
	fmt.Println(stdDevTime)

	min, err := stats.Min(duration)
	minTime := min / float64(time.Microsecond)
	if err != nil {
		panic(err)
	}
	fmt.Println("Min Time")
	fmt.Println(minTime)

	max, err := stats.Max(duration)
	maxTime := max / float64(time.Microsecond)
	if err != nil {
		panic(err)
	}
	fmt.Println("Max Time")
	fmt.Println(maxTime)

}

func benchMarkObo(users int, tokens int, client base.Client) {
	var duration []float64
	for start := time.Now(); time.Since(start) < time.Minute*1; {
		s := time.Now()
		queryCache(users, tokens, client)
		e := time.Now()
		duration = append(duration, float64(e.Sub(s)))
	}
	calculateStats(users, tokens, duration)
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
func TestOnBehalfOfCacheTests(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping testing in CI environment")
	}
	tests := []struct {
		Users  int
		Tokens int
	}{
		{1, 10000},
		{1, 100000},
		{100, 10000},
		{1000, 10000},
		{10000, 100},
	}

	for _, test := range tests {
		client, err := fakeClient()
		if err != nil {
			panic(err)
		}
		authParams := client.AuthParams
		populateCache(test.Users, test.Tokens, authParams, client)
		benchMarkObo(test.Users, test.Tokens, client)
	}
}
