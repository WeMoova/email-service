package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserContextKey contextKey = "user"

type JWTClaims struct {
	Sub   string   `json:"sub"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

var (
	jwksCache     *JWKS
	jwksCacheMux  sync.RWMutex
	jwksCacheTime time.Time
	cacheDuration = 24 * time.Hour
)

// JWTAuth middleware validates FusionAuth JWT tokens
func JWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondError(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			respondError(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(tokenString)
		if err != nil {
			respondError(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateToken(tokenString string) (*JWTClaims, error) {
	fusionAuthURL := os.Getenv("FUSIONAUTH_URL")
	if fusionAuthURL == "" {
		return nil, fmt.Errorf("FUSIONAUTH_URL not configured")
	}

	jwksURL := fmt.Sprintf("%s/.well-known/jwks.json", fusionAuthURL)

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get kid from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		// Fetch public key from JWKS
		publicKey, err := fetchPublicKey(jwksURL, kid)
		if err != nil {
			return nil, err
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

func fetchPublicKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	jwks, err := getJWKS(jwksURL)
	if err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return parseRSAPublicKey(key)
		}
	}

	return nil, fmt.Errorf("key with kid %s not found", kid)
}

func getJWKS(jwksURL string) (*JWKS, error) {
	// Check cache
	jwksCacheMux.RLock()
	if jwksCache != nil && time.Since(jwksCacheTime) < cacheDuration {
		defer jwksCacheMux.RUnlock()
		return jwksCache, nil
	}
	jwksCacheMux.RUnlock()

	// Fetch JWKS
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Update cache
	jwksCacheMux.Lock()
	jwksCache = &jwks
	jwksCacheTime = time.Now()
	jwksCacheMux.Unlock()

	return &jwks, nil
}

func parseRSAPublicKey(key JWK) (*rsa.PublicKey, error) {
	// Decode base64url encoded N and E
	nBytes, err := jwt.DecodeSegment(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}

	eBytes, err := jwt.DecodeSegment(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}

	// Convert bytes to big.Int
	var n, e int
	for _, b := range nBytes {
		n = n<<8 | int(b)
	}
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	// Note: This is a simplified version. In production, use a proper library
	// like github.com/lestrrat-go/jwx for full JWK support
	return &rsa.PublicKey{
		N: nil, // Would need proper conversion here
		E: e,
	}, fmt.Errorf("use github.com/lestrrat-go/jwx for proper JWK parsing")
}

func respondError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// GetUserFromContext retrieves user claims from request context
func GetUserFromContext(ctx context.Context) (*JWTClaims, error) {
	claims, ok := ctx.Value(UserContextKey).(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("user not found in context")
	}
	return claims, nil
}
