package providers

import (
	"context"
	"net/url"
	"bytes"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// TwitterProvider represents a Twitter based Identity Provider
type TwitterProvider struct {
	*ProviderData
	Users []string
}

var _ Provider = (*TwitterProvider)(nil)

const (
	twitterProviderName = "Twitter"
	twitterDefaultScope = "tweet.read users.read"
)

var (
	// Default Login URL for Twitter.
	// Pre-parsed URL of https://twitter.com/i/oauth2/authorize
	twitterDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "twitter.com",
		Path:   "/i/oauth2/authorize",
	}

	// Default Redeem URL for Twitter.
	// Pre-parsed URL of https://api.twitter.com/2/oauth2/token
	twitterDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "api.twitter.com",
		Path:   "/2/oauth2/token",
	}

	// Default Profile URL for Twitter.
	// Pre-parsed URL of https://api.twitter.com/2/users/me
	twitterDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "api.twitter.com",
		Path:   "/2/users/me",
	}
)

// NewTwitterProvider initiates a new TwitterProvider
func NewTwitterProvider(p *ProviderData) *TwitterProvider {
	p.setProviderDefaults(providerDefaults{
		name:        twitterProviderName,
		loginURL:    twitterDefaultLoginURL,
		redeemURL:   twitterDefaultRedeemURL,
		profileURL:  twitterDefaultProfileURL,
		validateURL: twitterDefaultProfileURL,
		scope:       twitterDefaultScope,
	})
	return &TwitterProvider{ProviderData: p}
}

// SetUsers configures allowed usernames
func (p *TwitterProvider) SetUsers(users []string) {
	p.Users = users
}

// GetLoginURL with typical oauth parameters
func (p *TwitterProvider) GetLoginURL(redirectURI, state, _ string) string {
	// https://developer.twitter.com/en/docs/authentication/oauth-2-0/user-access-token
	// ex. https://twitter.com/i/oauth2/authorize?response_type=code&client_id=rG9n6402A3dbUJKzXTNX4oWHJ&redirect_uri=https://www.example.com&scope=tweet.read%20users.read&state=state&code_challenge=challenge&code_challenge_method=plain
	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Add("code_challenge", "challenge")
	params.Add("code_challenge_method", "plain")
	a.RawQuery = params.Encode()
	return a.String()
}

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *TwitterProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}

	// ex. curl --location --request POST 'https://api.twitter.com/2/oauth2/token' \--header 'Content-Type: application/x-www-form-urlencoded' \--data-urlencode 'code=VGNibzFWSWREZm01bjN1N3dicWlNUG1oa2xRRVNNdmVHelJGY2hPWGxNd2dxOjE2MjIxNjA4MjU4MjU6MToxOmFjOjE' \--data-urlencode 'grant_type=authorization_code' \--data-urlencode 'client_id=rG9n6402A3dbUJKzXTNX4oWHJ \--data-urlencode 'redirect_uri=https://www.example.com' \--data-urlencode 'code_verifier=challenge'
	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("code", code)
	params.Add("code_verifier", "challenge")
	params.Add("grant_type", "authorization_code")

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	// blindly try json
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err := result.UnmarshalInto(&jsonResponse)
	if err == nil {
		return &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}, nil
	}

	return nil, fmt.Errorf("no access token found %s", result.Body())
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *TwitterProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if s.AccessToken == "" || p.Data().ProfileURL == nil || p.Data().ProfileURL.String() == "" {
		return fmt.Errorf("enrich session request failed")
	}

	header := makeAuthorizationHeader(tokenTypeBearer, s.AccessToken, nil)
	endpoint := p.Data().ProfileURL.String()

	result := requests.New(endpoint).
		WithContext(ctx).
		WithHeaders(header).
		Do()
	if result.Error() != nil {
		logger.Errorf("GET %s", stripToken(endpoint))
		logger.Errorf("enrich session request failed: %s", result.Error())
		return result.Error()
	}

	logger.Printf("%d GET %s %s", result.StatusCode(), stripToken(endpoint), result.Body())

	if result.StatusCode() != 200 {
		return fmt.Errorf("enrich session request failed: status %d - %s", result.StatusCode(), result.Body())
	}

	// {"data":{"id":"id","name":"name","username":"username"}}
	var jsonResponse struct {
		Data struct {
			Id string `json:"id"`
		}
	}
	err := result.UnmarshalInto(&jsonResponse)
	if err != nil {
		return fmt.Errorf("enrich session request failed: status %d - %s", result.StatusCode(), result.Body())
	}

	s.User = jsonResponse.Data.Id

	return nil
}

// ValidateSession validates the AccessToken
func (p *TwitterProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAuthorizationHeader(tokenTypeBearer, s.AccessToken, nil))
}

// Authorize performs global authorization on an authenticated session.
// This is not used for fine-grained per route authorization rules.
func (p *TwitterProvider) Authorize(_ context.Context, s *sessions.SessionState) (bool, error) {
	if len(p.Users) == 0 {
		return true, nil
	}
	for _, u := range p.Users {
		if s.User == u {
			return true, nil
		}
	}
	return false, nil
}
