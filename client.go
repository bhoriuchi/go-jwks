package jwks

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	defaultRequestTimeout = time.Duration(5)
	defaultCacheTimeout   = time.Duration(600)
)

// ErrKidNotFound kid was not found
var ErrKidNotFound = errors.New("kid was not found in the jwks")

// JSONWebKeySet a json web key set
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey a json web key
type JSONWebKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
}

// ClientOptions options for client
type ClientOptions struct {
	Insecure       bool
	CacheTimeout   *time.Duration
	RequestTimeout *time.Duration
	Logger         Logger
}

// Logger a common logging interface
type Logger interface {
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// NewClient creates a new JWKS client
func NewClient(endpoint string, options *ClientOptions) *Client {
	if options == nil {
		options = &ClientOptions{
			Insecure: false,
		}
	}

	if options.RequestTimeout == nil {
		var reqTimeout = defaultRequestTimeout
		options.RequestTimeout = &reqTimeout
	}

	if options.CacheTimeout == nil {
		var cacheTimeout = defaultCacheTimeout
		options.CacheTimeout = &cacheTimeout
	}

	client := Client{
		endpoint:       endpoint,
		insecure:       options.Insecure,
		requestTimeout: *options.RequestTimeout,
		cacheTimeout:   *options.CacheTimeout,
		logger:         options.Logger,
		mutex:          &sync.Mutex{},
		locked:         false,
		httpClient: &http.Client{
			Timeout: *options.RequestTimeout * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: options.Insecure},
			},
		},
	}
	return &client
}

// Client fetches a JWKS from specified endpoint
type Client struct {
	endpoint       string
	insecure       bool
	requestTimeout time.Duration
	cacheTimeout   time.Duration
	logger         Logger
	httpClient     *http.Client
	mutex          *sync.Mutex
	locked         bool
	jwks           *JSONWebKeySet
	quit           chan struct{}
}

// Keys returns the jwk keys
func (c *Client) Keys() []JSONWebKey {
	return c.jwks.Keys
}

// KeySet returns the entire jwks
func (c *Client) KeySet() *JSONWebKeySet {
	return c.jwks
}

// Start starts the client polling the jwks endpoint
func (c *Client) Start() error {
	ticker := time.NewTicker(c.cacheTimeout * time.Second)
	c.quit = make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := c.refresh(); err != nil {
					if c.logger != nil {
						c.logger.Errorf("failed to refresh jwks from endpoint, ending refresh")
					}
					return
				}
			case <-c.quit:
				ticker.Stop()
				return
			}
		}
	}()
	return c.refresh()
}

// Stop stops the jwks refresh
func (c *Client) Stop() {
	close(c.quit)
}

// locks the mutex
func (c *Client) lock() {
	if c.locked {
		c.mutex.Lock()
		c.unlock()
		return
	}
	c.locked = true
	c.mutex.Lock()
	return
}

// unlocks the mutex
func (c *Client) unlock() {
	c.mutex.Unlock()
	c.locked = false
}

// Refresh refreshes the JWKS
func (c *Client) refresh() error {
	c.lock()

	// attempt to fetch the keys
	if c.logger != nil {
		c.logger.Debugf("fetching JWKS from %q", c.endpoint)
	}
	resp, err := c.httpClient.Get(c.endpoint)

	// check the result
	if err != nil {
		c.unlock()
		return err
	} else if resp.StatusCode != http.StatusOK {
		c.unlock()
		return fmt.Errorf("fetch JWKS failed with status code %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// decode the json
	var jwks JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		c.unlock()
		return err
	}

	// set the keys
	c.jwks = &jwks
	if c.logger != nil {
		c.logger.Debugf("successfully refreshed JWKS from %q", c.endpoint)
	}
	c.unlock()

	return nil
}

// GetSigningKey gets the signing key from the kid
func GetSigningKey(kid string, jwks *JSONWebKeySet) (*JSONWebKey, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return &key, nil
		}
	}
	return nil, ErrKidNotFound
}

// GetSigningKey gets the verification key
func (c *Client) GetSigningKey(kid string) (*JSONWebKey, error) {
	return GetSigningKey(kid, c.jwks)
}

// KeyFunc gets the verify key from the keyset
func KeyFunc(jwks *JSONWebKeySet) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("no kid found in token")
		}
		signingKey, err := GetSigningKey(kid.(string), jwks)
		if err != nil {
			return nil, err
		}

		certString := x5cToString(signingKey.X5c)

		// convert the key to the appropriate cert type
		switch kty := signingKey.Kty; kty {
		case "RSA":
			return jwt.ParseRSAPublicKeyFromPEM([]byte(certString))
		case "EC":
			return jwt.ParseECPublicKeyFromPEM([]byte(certString))
		}

		return nil, fmt.Errorf("unsupported jwt algorithm %q", signingKey.Kty)
	}
}

// Parse parses a jwt using the current JWKS
func (c *Client) Parse(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, KeyFunc(c.jwks))
}

// IsValid checks if token is valid with recheck
func (c *Client) IsValid(tokenString string) (bool, *jwt.Token, error) {
	// attempt first parse
	token, err := c.Parse(tokenString)
	t, _ := json.MarshalIndent(token, "", "  ")
	fmt.Printf("%s\n", t)

	// check for token validity
	if err == ErrKidNotFound {
		// refresh if the kid was not found
		c.refresh()
	} else if err != nil {
		return false, token, err
	} else {
		return token.Valid, token, nil
	}

	// attempt second parse after refresh
	token, err = c.Parse(tokenString)
	if err != nil {
		return false, token, err
	}
	return token.Valid, token, nil
}

// convert the xc5 field to a pem
func x5cToString(x5c []string) string {
	str := ""
	for _, p := range x5c {
		str += fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", p)
	}
	return str
}
