package integration

import (
	"log"
	"net/http"
)

var defaultClient = &http.Client{}

func sendRequestToLab(url string, query map[string]string, accessToken string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	q := req.URL.Query()
	for key, value := range query {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()
	res, err := defaultClient.Do(req)
	if err != nil {
		return res, err
	}
	return res, nil
}
