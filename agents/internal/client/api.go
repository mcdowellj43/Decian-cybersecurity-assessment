package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"decian-agent/internal/logger"
)

var ErrUnauthorized = errors.New("unauthorized")

// APIClient handles communication with the Decian jobs API
// It is safe for reuse across goroutines
type APIClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *logger.Logger
}

func NewAPIClient(baseURL string, log *logger.Logger) *APIClient {
	return &APIClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     log,
	}
}

type RegisterRequest struct {
	OrgID       string            `json:"orgId"`
	Hostname    string            `json:"hostname"`
	Version     string            `json:"version"`
	EnrollToken string            `json:"enrollToken"`
	Labels      map[string]string `json:"labels"`
}

type RegisterResponse struct {
	AgentID     string `json:"agentId"`
	AgentSecret string `json:"agentSecret"`
}

type TokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
}

type JobEnvelope struct {
	JobID   string                 `json:"jobId"`
	Type    string                 `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

type ResultPayload struct {
	Status      string                 `json:"status"`
	Summary     map[string]interface{} `json:"summary"`
	ArtifactURL string                 `json:"artifactUrl,omitempty"`
}

type SignedUpload struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Expires string            `json:"expiresAt"`
}

func (c *APIClient) RegisterAgent(req RegisterRequest) (*RegisterResponse, error) {
	body, err := c.doRequest(http.MethodPost, "/api/agents/register", nil, req, "")
	if err != nil {
		return nil, err
	}

	var response struct {
		Status string           `json:"status"`
		Data   RegisterResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	return &response.Data, nil
}

func (c *APIClient) MintAgentToken(agentID, agentSecret string) (*TokenResponse, error) {
	authValue := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", agentID, agentSecret)))
	headers := map[string]string{"Authorization": "Basic " + authValue}

	body, err := c.doRequest(http.MethodPost, fmt.Sprintf("/api/agents/%s/tokens", url.PathEscape(agentID)), headers, nil, "")
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to mint agent token: %w", err)
	}

	var response struct {
		Status string        `json:"status"`
		Data   TokenResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	return &response.Data, nil
}

func (c *APIClient) NextJobs(agentID, token string, waitSeconds int) ([]JobEnvelope, error) {
	query := fmt.Sprintf("?wait=%d", waitSeconds)
	headers := map[string]string{"Authorization": "Bearer " + token}
	body, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/agents/%s/next-jobs%s", url.PathEscape(agentID), query), headers, nil, "")
	if err != nil {
		return nil, err
	}

	var response struct {
		Status string        `json:"status"`
		Data   []JobEnvelope `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse jobs response: %w", err)
	}
	return response.Data, nil
}

func (c *APIClient) AckJob(jobID, token string) error {
	return c.simpleJobCall(http.MethodPost, fmt.Sprintf("/api/jobs/%s/ack", url.PathEscape(jobID)), token)
}

func (c *APIClient) StartJob(jobID, token string) error {
	return c.simpleJobCall(http.MethodPost, fmt.Sprintf("/api/jobs/%s/start", url.PathEscape(jobID)), token)
}

func (c *APIClient) SubmitJobResults(jobID, token string, payload ResultPayload) error {
	headers := map[string]string{"Authorization": "Bearer " + token}
	_, err := c.doRequest(http.MethodPut, fmt.Sprintf("/api/jobs/%s/results", url.PathEscape(jobID)), headers, payload, "")
	return err
}

func (c *APIClient) SignArtifactUpload(jobID, token string) (*SignedUpload, error) {
	headers := map[string]string{"Authorization": "Bearer " + token}
	body, err := c.doRequest(http.MethodPost, fmt.Sprintf("/api/jobs/%s/artifacts/sign-put", url.PathEscape(jobID)), headers, nil, "")
	if err != nil {
		return nil, err
	}

	var response struct {
		Status string       `json:"status"`
		Data   SignedUpload `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse artifact response: %w", err)
	}
	return &response.Data, nil
}

func (c *APIClient) simpleJobCall(method, path, token string) error {
	headers := map[string]string{"Authorization": "Bearer " + token}
	_, err := c.doRequest(method, path, headers, nil, "")
	return err
}

func (c *APIClient) doRequest(method, path string, headers map[string]string, payload interface{}, contentType string) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request payload: %w", err)
		}
		body = bytes.NewBuffer(data)
		if contentType == "" {
			contentType = "application/json"
		}
	}

	endpoint := c.baseURL + path
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "Decian-Agent/1.0.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("api error: %s", http.StatusText(resp.StatusCode))
	}

	return data, nil
}
