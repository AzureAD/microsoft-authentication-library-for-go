// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"text/template"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

const accessToken = "fake_token"

var tokenScope = []string{"fake_scope"}

type testParams struct {
	// the number of goroutines to use
	Concurrency int

	// the number of tokens in the cache
	// must be divisible by Concurrency
	TokenCount int
}

func fakeClient() (base.Client, error) {
	// we use a base.Client so we can provide a fake OAuth client
	return base.New("fake_client_id", "https://fake_authority/fake", &oauth.Client{
		AccessTokens: &fake.AccessTokens{
			AccessToken: accesstokens.TokenResponse{
				AccessToken:   accessToken,
				ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
				GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
			},
		},
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

type execTime struct {
	start time.Time
	end   time.Time
}

func populateTokenCache(client base.Client, params testParams) execTime {
	if r := params.TokenCount % params.Concurrency; r != 0 {
		panic("TokenCount must be divisible by Concurrency")
	}
	parts := params.TokenCount / params.Concurrency
	authParams := client.AuthParams
	authParams.Scopes = tokenScope
	authParams.AuthorizationType = authority.ATClientCredentials

	wg := &sync.WaitGroup{}
	fmt.Printf("Populating token cache with %d tokens...", params.TokenCount)
	start := time.Now()
	for n := 0; n < params.Concurrency; n++ {
		wg.Add(1)
		go func(chunk int) {
			for i := parts * chunk; i < parts*(chunk+1); i++ {
				// we use this to add a fake token to the cache.
				// each token has a different scope which is what makes them unique
				_, err := client.AuthResultFromToken(context.Background(), authParams, accesstokens.TokenResponse{
					AccessToken:   accessToken,
					ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
					GrantedScopes: accesstokens.Scopes{Slice: []string{strconv.FormatInt(int64(i), 10)}},
				}, true)
				if err != nil {
					panic(err)
				}
			}
			wg.Done()
		}(n)
	}
	wg.Wait()
	return execTime{start: start, end: time.Now()}
}

func executeTest(client base.Client, params testParams) execTime {
	wg := &sync.WaitGroup{}
	fmt.Printf("Begin token retrieval.....")
	start := time.Now()
	for n := 0; n < params.Concurrency; n++ {
		wg.Add(1)
		go func() {
			// retrieve each token once per goroutine
			for tk := 0; tk < params.TokenCount; tk++ {
				_, err := client.AcquireTokenSilent(context.Background(), base.AcquireTokenSilentParameters{
					Scopes:      []string{strconv.FormatInt(int64(tk), 10)},
					RequestType: accesstokens.ATConfidential,
					Credential: &accesstokens.Credential{
						Secret: "fake_secret",
					},
				})
				if err != nil {
					panic(err)
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
	return execTime{start: start, end: time.Now()}
}

// Stats is used with statsTemplText for reporting purposes
type Stats struct {
	popExec     execTime
	retExec     execTime
	Concurrency int
	Count       int64
}

// PopDur returns the total duration for populating the cache.
func (s *Stats) PopDur() time.Duration {
	return s.popExec.end.Sub(s.popExec.start)
}

// RetDur returns the total duration for retrieving tokens.
func (s *Stats) RetDur() time.Duration {
	return s.retExec.end.Sub(s.retExec.start)
}

// PopAvg returns the mean average of caching a token.
func (s *Stats) PopAvg() time.Duration {
	return s.PopDur() / time.Duration(s.Count)
}

// RetAvg returns the mean average of retrieving a token.
func (s *Stats) RetAvg() time.Duration {
	return s.RetDur() / time.Duration(s.Count)
}

var statsTemplText = `
Test Results:
[{{.Concurrency}} goroutines][{{.Count}} tokens] [population: total {{.PopDur}}, avg {{.PopAvg}}] [retrieval: total {{.RetDur}}, avg {{.RetAvg}}]
==========================================================================
`
var statsTempl = template.Must(template.New("stats").Parse(statsTemplText))

func main() {
	tests := []testParams{
		{
			Concurrency: runtime.NumCPU(),
			TokenCount:  100,
		},
		{
			Concurrency: runtime.NumCPU(),
			TokenCount:  1000,
		},
		{
			Concurrency: runtime.NumCPU(),
			TokenCount:  10000,
		},
		{
			Concurrency: runtime.NumCPU(),
			TokenCount:  20000,
		},
	}

	for _, t := range tests {
		client, err := fakeClient()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Test Params: %#v\n", t)
		ptime := populateTokenCache(client, t)
		ttime := executeTest(client, t)
		if err := statsTempl.Execute(os.Stdout, &Stats{
			popExec:     ptime,
			retExec:     ttime,
			Concurrency: t.Concurrency,
			Count:       int64(t.TokenCount),
		}); err != nil {
			panic(err)
		}
	}
}
