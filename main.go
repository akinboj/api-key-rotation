package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type KeyManager struct {
	mu         sync.RWMutex
	currentKey jwk.Set
	privateKey *rsa.PrivateKey
	clientID   string
}

func NewKeyManager() (*KeyManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	publicKey := privateKey.Public()

	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	kid := uuid.New().String()
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, fmt.Errorf("failed to add key to JWK set: %w", err)
	}

	return &KeyManager{
		currentKey: set,
		privateKey: privateKey,
		clientID:   "fea0ed84-4c79-4d3b-8ab3-04eaa0e01c39", // Replace with your actual client ID
	}, nil
}

func (km *KeyManager) RotateKeys() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate new RSA key: %w", err)
	}

	publicKey := privateKey.Public()

	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create JWK: %w", err)
	}

	kid := uuid.New().String()
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}

	newSet := jwk.NewSet()
	if err := newSet.AddKey(key); err != nil {
		return fmt.Errorf("failed to add key to JWK set: %w", err)
	}

	km.currentKey = newSet
	km.privateKey = privateKey

	log.Println("Keys rotated successfully")
	return nil
}

func (km *KeyManager) ServeJWK(w http.ResponseWriter, r *http.Request) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(km.currentKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (km *KeyManager) GenerateClientAssertion(tokenEndpoint string) (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": km.clientID,
		"iss": km.clientID,
		"aud": tokenEndpoint,
		"jti": uuid.New().String(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Get the current key ID from the JWK set
	if key, ok := km.currentKey.Key(0); ok {
		if kid, ok := key.Get("kid"); ok {
			token.Header["kid"] = kid
		}
	}

	// Sign the token with the private key
	signedToken, err := token.SignedString(km.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func (km *KeyManager) HandleClientAssertion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenEndpoint := "https://iam-digital-gateway.site-a:30415/realms/send-inbasket/protocol/openid-connect/token"
	assertion, err := km.GenerateClientAssertion(tokenEndpoint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"client_assertion": assertion,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func loadUnencryptedKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read certificate file: %v", err)
	}

	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read key file: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load X509 key pair: %v", err)
	}

	return cert, nil
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Application Server Health Check: OK")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Application Server Health Check is OK"))
}

func main() {
	keyManager, err := NewKeyManager()
	if err != nil {
		log.Fatal(err)
	}

	// Register handlers
	http.HandleFunc("/.well-known/jwks.json", keyManager.ServeJWK)
	http.HandleFunc("/client-assertion", keyManager.HandleClientAssertion)
	http.HandleFunc("/health", healthCheckHandler)

	// Key rotation goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			err := keyManager.RotateKeys()
			if err != nil {
				log.Println("Error rotating keys:", err)
			}
		}
	}()

	certFile := "/app/certs/jwk-gateway-api.site-a.pem"
	keyFile := "/app/certs/jwk-gateway-api.site-a-key.pem"

	cert, err := loadUnencryptedKeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load certificate and key: %v", err)
	}

	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Println("Server listening on port 8443 (HTTPS)")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
