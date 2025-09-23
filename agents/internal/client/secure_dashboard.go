package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SecureDashboardClient handles secure communication with the Decian dashboard
type SecureDashboardClient struct {
	baseURL           string
	token             string
	encryptionKey     []byte
	hmacKey           []byte
	pinnedCertHashes  []string
	httpClient        *http.Client
	logger            *logger.Logger
	maxRetries        int
	retryDelay        time.Duration
	compressionLevel  int
}

// SecureClientConfig contains configuration for secure communication
type SecureClientConfig struct {
	BaseURL           string
	Token             string
	EncryptionKey     string        // Base64 encoded 32-byte key
	HMACKey           string        // Base64 encoded 32-byte key
	PinnedCertHashes  []string      // SHA256 hashes of pinned certificates
	MaxRetries        int
	RetryDelay        time.Duration
	CompressionLevel  int
	ClientCertPath    string // Path to client certificate for mutual TLS
	ClientKeyPath     string // Path to client private key
}

// EncryptedPayload represents an encrypted message
type EncryptedPayload struct {
	Data      string `json:"data"`      // Base64 encoded encrypted data
	IV        string `json:"iv"`        // Base64 encoded initialization vector
	HMAC      string `json:"hmac"`      // Base64 encoded HMAC signature
	Timestamp int64  `json:"timestamp"` // Unix timestamp for replay protection
}

// NewSecureDashboardClient creates a new secure dashboard client
func NewSecureDashboardClient(config SecureClientConfig, logger *logger.Logger) (*SecureDashboardClient, error) {
	// Decode encryption keys
	encryptionKey, err := base64.StdEncoding.DecodeString(config.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes")
	}

	hmacKey, err := base64.StdEncoding.DecodeString(config.HMACKey)
	if err != nil {
		return nil, fmt.Errorf("invalid HMAC key: %w", err)
	}
	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("HMAC key must be 32 bytes")
	}

	// Create TLS configuration with security enhancements
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		InsecureSkipVerify: false,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyPinnedCertificate(rawCerts, config.PinnedCertHashes)
		},
	}

	// Load client certificate for mutual TLS if provided
	if config.ClientCertPath != "" && config.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Set default values
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = time.Second
	}

	// Create HTTP client with secure transport
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		DisableCompression:  false,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	return &SecureDashboardClient{
		baseURL:           config.BaseURL,
		token:             config.Token,
		encryptionKey:     encryptionKey,
		hmacKey:           hmacKey,
		pinnedCertHashes:  config.PinnedCertHashes,
		httpClient:        client,
		logger:            logger,
		maxRetries:        config.MaxRetries,
		retryDelay:        config.RetryDelay,
		compressionLevel:  config.CompressionLevel,
	}, nil
}

// verifyPinnedCertificate verifies that at least one certificate matches the pinned hashes
func verifyPinnedCertificate(rawCerts [][]byte, pinnedHashes []string) error {
	if len(pinnedHashes) == 0 {
		return nil // No pinning configured
	}

	for _, rawCert := range rawCerts {
		hash := sha256.Sum256(rawCert)
		certHash := base64.StdEncoding.EncodeToString(hash[:])

		for _, pinnedHash := range pinnedHashes {
			if certHash == pinnedHash {
				return nil // Certificate matches pinned hash
			}
		}
	}

	return fmt.Errorf("certificate does not match any pinned hash")
}

// encryptPayload encrypts data using AES-256-GCM
func (c *SecureDashboardClient) encryptPayload(data []byte) (*EncryptedPayload, error) {
	// Create AES cipher
	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Create HMAC
	hmacHash := hmac.New(sha256.New, c.hmacKey)
	timestamp := time.Now().Unix()
	hmacData := append(ciphertext, nonce...)
	hmacData = append(hmacData, []byte(fmt.Sprintf("%d", timestamp))...)
	hmacHash.Write(hmacData)
	signature := hmacHash.Sum(nil)

	return &EncryptedPayload{
		Data:      base64.StdEncoding.EncodeToString(ciphertext),
		IV:        base64.StdEncoding.EncodeToString(nonce),
		HMAC:      base64.StdEncoding.EncodeToString(signature),
		Timestamp: timestamp,
	}, nil
}

// decryptPayload decrypts an encrypted payload
func (c *SecureDashboardClient) decryptPayload(payload *EncryptedPayload) ([]byte, error) {
	// Decode components
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(payload.HMAC)
	if err != nil {
		return nil, fmt.Errorf("failed to decode HMAC: %w", err)
	}

	// Verify timestamp (prevent replay attacks)
	now := time.Now().Unix()
	if now-payload.Timestamp > 300 { // 5 minutes
		return nil, fmt.Errorf("payload timestamp too old")
	}

	// Verify HMAC
	hmacHash := hmac.New(sha256.New, c.hmacKey)
	hmacData := append(ciphertext, nonce...)
	hmacData = append(hmacData, []byte(fmt.Sprintf("%d", payload.Timestamp))...)
	hmacHash.Write(hmacData)
	expectedSignature := hmacHash.Sum(nil)

	if !hmac.Equal(signature, expectedSignature) {
		return nil, fmt.Errorf("HMAC verification failed")
	}

	// Create AES cipher
	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// makeSecureRequest makes an encrypted HTTP request with retry logic
func (c *SecureDashboardClient) makeSecureRequest(method, endpoint string, payload interface{}, response interface{}) error {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		err := c.attemptSecureRequest(method, endpoint, payload, response)
		if err == nil {
			return nil
		}

		lastErr = err
		c.logger.Warn("Request attempt failed", map[string]interface{}{
			"attempt": attempt + 1,
			"error":   err.Error(),
		})

		if attempt < c.maxRetries {
			// Exponential backoff
			delay := c.retryDelay * time.Duration(1<<attempt)
			c.logger.Debug("Retrying request", map[string]interface{}{
				"delay": delay,
			})
			time.Sleep(delay)
		}
	}

	return fmt.Errorf("request failed after %d attempts: %w", c.maxRetries+1, lastErr)
}

// attemptSecureRequest makes a single secure request attempt
func (c *SecureDashboardClient) attemptSecureRequest(method, endpoint string, payload interface{}, response interface{}) error {
	url := c.baseURL + endpoint

	var body *bytes.Buffer
	if payload != nil {
		// Marshal payload to JSON
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal request payload: %w", err)
		}

		// Encrypt payload
		encryptedPayload, err := c.encryptPayload(jsonData)
		if err != nil {
			return fmt.Errorf("failed to encrypt payload: %w", err)
		}

		// Marshal encrypted payload
		encryptedData, err := json.Marshal(encryptedPayload)
		if err != nil {
			return fmt.Errorf("failed to marshal encrypted payload: %w", err)
		}

		body = bytes.NewBuffer(encryptedData)
	} else {
		body = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", "Decian-Agent-Secure/2.0.0")
	req.Header.Set("X-Request-ID", generateRequestID())
	req.Header.Set("X-Encrypted", "true")

	c.logger.Debug("Making secure API request", map[string]interface{}{
		"method": method,
		"url":    url,
	})

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	c.logger.Debug("Secure API response", map[string]interface{}{
		"status_code": resp.StatusCode,
	})

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	// Decode response if needed
	if response != nil {
		// Check if response is encrypted
		if resp.Header.Get("X-Encrypted") == "true" {
			var encryptedResponse EncryptedPayload
			if err := json.NewDecoder(resp.Body).Decode(&encryptedResponse); err != nil {
				return fmt.Errorf("failed to decode encrypted response: %w", err)
			}

			// Decrypt response
			decryptedData, err := c.decryptPayload(&encryptedResponse)
			if err != nil {
				return fmt.Errorf("failed to decrypt response: %w", err)
			}

			// Decode decrypted data
			if err := json.Unmarshal(decryptedData, response); err != nil {
				return fmt.Errorf("failed to decode decrypted response: %w", err)
			}
		} else {
			// Plain response
			if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}
		}
	}

	return nil
}

// generateRequestID generates a unique request ID for correlation
func generateRequestID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// RegisterAgent registers the agent with the dashboard using secure communication
func (c *SecureDashboardClient) RegisterAgent(hostname, version string, config map[string]interface{}) (*Agent, error) {
	payload := map[string]interface{}{
		"hostname":      hostname,
		"version":       version,
		"configuration": config,
		"secureMode":    true,
	}

	var response struct {
		APIResponse
		Data struct {
			Agent Agent `json:"agent"`
		} `json:"data"`
	}

	err := c.makeSecureRequest("POST", "/api/agents/register", payload, &response)
	if err != nil {
		return nil, err
	}

	return &response.Data.Agent, nil
}

// GetAgentStatus retrieves the current agent status securely
func (c *SecureDashboardClient) GetAgentStatus(agentID string) (*Agent, error) {
	var response struct {
		APIResponse
		Data struct {
			Agent Agent `json:"agent"`
		} `json:"data"`
	}

	err := c.makeSecureRequest("GET", fmt.Sprintf("/api/agents/%s", agentID), nil, &response)
	if err != nil {
		return nil, err
	}

	return &response.Data.Agent, nil
}

// SendHeartbeat sends a secure heartbeat to update agent status
func (c *SecureDashboardClient) SendHeartbeat(agentID string, metadata map[string]interface{}) error {
	payload := map[string]interface{}{
		"status":     "ONLINE",
		"metadata":   metadata,
		"secureMode": true,
		"timestamp":  time.Now().Unix(),
	}

	var response APIResponse
	return c.makeSecureRequest("POST", fmt.Sprintf("/api/agents/%s/heartbeat", agentID), payload, &response)
}

// GetPendingAssessments retrieves any pending assessments for the agent securely
func (c *SecureDashboardClient) GetPendingAssessments(agentID string) ([]Assessment, error) {
	var response struct {
		APIResponse
		Data struct {
			Assessments []Assessment `json:"assessments"`
		} `json:"data"`
	}

	err := c.makeSecureRequest("GET", fmt.Sprintf("/api/assessments?agentId=%s&status=PENDING", agentID), nil, &response)
	if err != nil {
		return nil, err
	}

	return response.Data.Assessments, nil
}

// SubmitResults submits assessment results to the dashboard securely
func (c *SecureDashboardClient) SubmitResults(agentID string, results []modules.AssessmentResult, overallRisk float64) error {
	// Convert modules.AssessmentResult to API format
	apiResults := make([]map[string]interface{}, len(results))
	for i, result := range results {
		apiResults[i] = map[string]interface{}{
			"checkType":  result.CheckType,
			"resultData": result.Data,
			"riskScore":  result.RiskScore,
			"riskLevel":  result.RiskLevel,
			"timestamp":  result.Timestamp,
			"duration":   result.Duration,
		}
	}

	payload := map[string]interface{}{
		"results":          apiResults,
		"overallRiskScore": overallRisk,
		"secureMode":       true,
		"submissionTime":   time.Now().Unix(),
	}

	// First, get pending assessment for this agent
	assessments, err := c.GetPendingAssessments(agentID)
	if err != nil {
		return fmt.Errorf("failed to get pending assessments: %w", err)
	}

	if len(assessments) == 0 {
		return fmt.Errorf("no pending assessments found for agent")
	}

	// Submit results to the first pending assessment
	assessmentID := assessments[0].ID
	var response APIResponse
	return c.makeSecureRequest("PUT", fmt.Sprintf("/api/assessments/%s/results", assessmentID), payload, &response)
}

// Close closes the secure client and cleans up resources
func (c *SecureDashboardClient) Close() error {
	// Clear sensitive data from memory
	for i := range c.encryptionKey {
		c.encryptionKey[i] = 0
	}
	for i := range c.hmacKey {
		c.hmacKey[i] = 0
	}

	// Close HTTP client transport
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}

	return nil
}