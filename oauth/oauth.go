package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"net/http"
	"./error"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic = "X-Public"
	headerXClient = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		Headers:        nil,
		Timeout:        200 * time.Millisecond,
		ConnectTimeout: 0,
		BaseURL:        "http://localhost:8080",
		ContentType:    0,
		DisableCache:   false,
		DisableTimeout: false,
		FollowRedirect: false,
		CustomPool:     nil,
		BasicAuth:      nil,
		UserAgent:      "",
		Client:         nil,
	}
)

type accessToken struct {
	Id string `json:"id"`
	UserId int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return  0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64  {
	if request == nil {
		return  0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClient), 10, 64)
	if err != nil {
		return 0
	}

	return clientId
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))

	if accessTokenId == "" {
		return nil
	}
	
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}
	
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(headerXClient, fmt.Sprintf("%v", at.ClientId))

	return  nil
}

func cleanRequest(request *http.Request)  {
	if request == nil {
		return
	}

	request.Header.Del(headerXClient)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if response == nil || response.Request == nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to login user")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to login user")
		}

		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshall users response")
	}

	return &at, nil
}