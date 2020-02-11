package auth0

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	gjwt "github.com/gbrlsnchs/jwt/v3"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func TestValidate(t *testing.T) {
	type args struct {
		payload  *gjwt.Payload
		audience string
		issuer   string
	}

	now := time.Now()
	// Signer
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	rsa256 := gjwt.NewRS256(gjwt.RSAPrivateKey(privateKey))
	kid := "MEZCQTU1NTY5QjY4MDcxQkQ2MUJBQzVGNjQ1QjZGNEFBMzkxMzk0NA"

	testCases := []struct {
		name string
		args args
		want bool // indicates if there should be an error
	}{
		{"successful validation", args{
			payload: &gjwt.Payload{
				Issuer:         "https://test-spt.auth0.com/",
				Subject:        "PLPO8UzEmORjVEGOcmJ46TzG9ANe57p5@clientss",
				Audience:       []string{"https://test-spt.auth0.com/api/v2/"},
				ExpirationTime: &gjwt.Time{now.Add(24 * 30 * 12 * time.Hour)},
				NotBefore:      &gjwt.Time{now.Add(time.Duration(-10) * time.Minute)},
				IssuedAt:       &gjwt.Time{now},
			},
			audience: "https://test-spt.auth0.com/api/v2/",
			issuer:   "https://test-spt.auth0.com/",
		},
			false},
		{"wrong issuer ", args{
			payload: &gjwt.Payload{
				Issuer:         "https://test-spt.auth0.com/",
				Subject:        "PLPO8UzEmORjVEGOcmJ46TzG9ANe57p5@clientss",
				Audience:       []string{"https://test-spt.auth0.com/api/v2/"},
				ExpirationTime: &gjwt.Time{now.Add(24 * 30 * 12 * time.Hour)},
				NotBefore:      &gjwt.Time{now.Add(time.Duration(-10) * time.Minute)},
				IssuedAt:       &gjwt.Time{now},
			},
			audience: "https://test-spt.auth0.com/api/v2/",
			issuer:   "https://wrong.issuer.com/",
		},
			true},
		{"wrong audience", args{
			payload: &gjwt.Payload{
				Issuer:         "https://test-spt.auth0.com/",
				Subject:        "PLPO8UzEmORjVEGOcmJ46TzG9ANe57p5@clientss",
				Audience:       []string{"https://test-spt.auth0.com/api/v2/"},
				ExpirationTime: &gjwt.Time{now.Add(24 * 30 * 12 * time.Hour)},
				NotBefore:      &gjwt.Time{now.Add(time.Duration(-10) * time.Minute)},
				IssuedAt:       &gjwt.Time{now},
			},
			audience: "https://wrong.audience.com/api/v2/",
			issuer:   "https://test-spt.auth0.com/",
		},
			true},
	}

	auth0 := NewAuth0(1, 5)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() { auth0.cache.Purge() }()
			tokenBytes, err := gjwt.Sign(&tc.args.payload, rsa256, gjwt.KeyID(kid))
			if err != nil {
				t.Errorf("Sign() failed: %v", err)
			}
			accessToken := fmt.Sprintf("Bearer %s", string(tokenBytes))

			JwkFetch = func(urlstring string, options ...jwt.Option) (*jwk.Set, error) {
				key, err := jwk.New(make([]byte, 64))
				if err != nil {
					t.Fatalf("jwk.New failed: %v", err)
				}
				set := &jwk.Set{Keys: []jwk.Key{key}}
				return set, nil
			}

			JwsVerifyWithJWK = func(buf []byte, key jwk.Key) (payload []byte, err error) {
				return []byte("verified"), nil
			}

			_, err = auth0.Validate("https://example.autho.com/jwks.json",
				tc.args.audience,
				tc.args.issuer,
				accessToken)

			if (err != nil) != tc.want {
				t.Errorf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}
}
