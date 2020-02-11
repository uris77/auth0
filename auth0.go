package auth0

import (
	"errors"
	"strings"
	"time"

	"github.com/apibillme/cache"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/lestrrat-go/jwx/jwk"
)

// reference vars here for stubbing
var JwkFetch = jwk.Fetch
var JwsVerifyWithJWK = jws.VerifyWithJWK
var jwtParseString = jwt.ParseString

// Retrieve the JWKs and validate the token against it.
func validateToken(jwkURL string, jwtToken string) (*jwt.Token, error) {
	// get JWKs and validate them against JWT token
	set, err := JwkFetch(jwkURL)
	if err != nil {
		return nil, err
	}

	var errstrings []string

	matches := 0
	for _, key := range set.Keys {
		_, err = JwsVerifyWithJWK([]byte(jwtToken), key)
		if err == nil {
			matches++
		} else {
			errstrings = append(errstrings, err.Error())
		}
	}

	// if JWT validated then verify token
	if matches > 0 {
		return verifyToken(jwtToken)
	}

	// token is invalid
	return nil, errors.New(strings.Join(errstrings, "\n"))
}

// Verifies the token's claims
func verifyToken(jwtToken string) (*jwt.Token, error) {
	// parse & verify claims of JWT token
	token, err := jwtParseString(jwtToken)
	if err != nil {
		return nil, err
	}
	err = token.Verify()
	if err != nil {
		return nil, err
	}
	return token, nil
}

// Verifies that the token has a Bearer.
// The token will originally be a string that is sent via an HTTP header with the format:
// "Bearer tokaernadfasfaf"
// Since we only expect the token to be sent via an http request through its header, checking for
// the `Bearer` string is an extra mechanism for making sure the lambda is not being misused.
func verifyBearerToken(tokenParts []string) (string, error) {
	if len(tokenParts) < 2 {
		return "", errors.New("Authorization header must have a Bearer token")
	}
	if tokenParts[0] != "Bearer" {
		return "", errors.New("Authorization header must have a Bearer token")
	}
	return tokenParts[1], nil
}

// Process a token by validating it and verifying the token's claims.
func (a Auth0) processToken(jwtToken string, jwkURL string, audience string, issuer string) (*jwt.Token, error) {
	// check if token is in cache
	_, ok := a.cache.Get(jwtToken)

	// if not then validate & verify token and save in db
	if !ok {
		token, err := validateToken(jwkURL, jwtToken)
		if err != nil {
			return nil, err
		}
		// validate audience
		if token.Audience()[0] != audience {
			return nil, errors.New("audience is not valid")
		}
		// validate issuer
		if token.Issuer() != issuer {
			return nil, errors.New("issuer is not valid")
		}

		// set in cache
		a.cache.Set(jwtToken, jwtToken)
	}

	// if so then only verify token
	return verifyToken(jwtToken)
}

type Auth0 struct {
	cache cache.Cache
}

// Create a new Auth0 client.
// keyCapacity indicates the maximum number of keys the Cache will hold.
// ttl is the time to live in seconds for keys to live in the Cache.
func NewAuth0(keyCapacity int, ttl int64) Auth0 {
	globalTTL := time.Duration(ttl)
	Cached := cache.New(keyCapacity, cache.WithTTL(globalTTL*time.Second))
	return Auth0{cache: Cached}
}

// Validate - validate with JWK & JWT Auth0 & audience & issuer for net/http
func (a Auth0) Validate(jwkURL string, audience string, issuer string, jwtToken string) (*jwt.Token, error) {
	// process token
	tokenParts := strings.Split(jwtToken, " ")
	token, err := verifyBearerToken(tokenParts)
	if err != nil {
		return nil, err
	}
	return a.processToken(token, jwkURL, audience, issuer)
}
