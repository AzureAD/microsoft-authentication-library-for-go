package integrationtests

import (
	"io/ioutil"
	"log"
	"net/http"
)

var defaultClient = &http.Client{}

func sendRequestToLab(url string, query map[string]string, accessToken string) ([]byte, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	q := request.URL.Query()
	for key, value := range query {
		q.Add(key, value)
	}
	request.URL.RawQuery = q.Encode()
	response, err := defaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	return body, nil
}
