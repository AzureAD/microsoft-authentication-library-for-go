package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/AzureAD/microsoft-authentication-library-for-go/broker"
)

var (
	clientID    = flag.String("clientID", "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "")
	path        = flag.String("path", "./msalruntime.dll", "")
	redirectURI = flag.String("redirectURI", "http://localhost:8181", "")
	scope       = flag.String("scope", "https://management.azure.com/.default", "")
	silent      = flag.Bool("silent", false, "attempt silent auth before interactive")
)

func main() {
	flag.Parse()

	err := broker.Initialize(*path)
	if err != nil {
		fmt.Printf("❌ error: %q\n", err)
		return
	}

	pca, err := public.New(*clientID, public.WithBroker(public.BrokerOptions{
		ListOperatingSystemAccounts: true,
	}))
	if err != nil {
		fmt.Printf("❌ error: %q\n", err)
		return
	}

	var ar public.AuthResult
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *silent {
		a := public.Account{}
		b, err := os.ReadFile("account.json")
		if err == nil {
			err = json.Unmarshal(b, &a)
		}
		if err != nil {
			fmt.Printf("❌ can't silently authenticate because account.json is unreadable: %q\n", err)
			return
		}
		ar, err = pca.AcquireTokenSilent(ctx, []string{*scope}, public.WithSilentAccount(a))
		if err == nil {
			fmt.Println("✅ silent auth succeeded")
			printResult(ar, err)
			return
		}
		fmt.Printf("❌ silent auth failed: %q\n", err)
	}
	ar, err = pca.AcquireTokenInteractive(ctx, []string{*scope}, public.WithRedirectURI(*redirectURI))
	printResult(ar, err)
	b, err := json.Marshal(ar.Account)
	if err == nil {
		os.WriteFile("account.json", b, 0600)
	}
}

func printResult(ar public.AuthResult, err error) {
	result := &bytes.Buffer{}
	if err == nil {
		if b, er := json.Marshal(ar); er == nil {
			err = json.Indent(result, b, "", "\t")
		} else {
			err = er
		}
	}
	if err != nil {
		fmt.Printf("❌ error: %q\n", err)
	} else {
		fmt.Println(result)
	}
}
