package client

import (
	"bytes"
	"decian-agent/internal/logger"
	"decian-agent/internal/modules"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DashboardClient handles communication with the Decian dashboard
type DashboardClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
	logger     *logger.Logger
}

// Agent represents agent information from the dashboard
type Agent struct {
	ID       string     `json:"id"`
	Hostname string     `json:"hostname"`
	Version  string     `json:"version"`
	Status   string     `json:"status"`
	LastSeen *time.Time `json:"lastSeen"`
}

// Assessment represents an assessment from the dashboard
type Assessment struct {
	ID       string `json:"id"`
	AgentID  string `json:"agentId"`
	Status   string `json:"status"`
	Modules  []string `json:"modules"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// NewDashboardClient creates a new dashboard client
func NewDashboardClient(baseURL, token string, logger *logger.Logger) *DashboardClient {
	return &DashboardClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// RegisterAgent registers the agent with the dashboard
func (c *DashboardClient) RegisterAgent(organizationId, hostname, version string, config map[string]interface{}) (*Agent, error) {
	payload := map[string]interface{}{
		"organizationId": organizationId,
		"hostname":       hostname,
		"version":        version,
		"configuration":  config,
	}

	var response struct {
		APIResponse
		Data struct {
			Agent Agent `json:"agent"`
		} `json:"data"`
	}

	err := c.makeRequest("POST", "/api/agents/register", payload, &response)
	if err != nil {
		return nil, err
	}

	return &response.Data.Agent, nil
}

// GetAgentStatus retrieves the current agent status
func (c *DashboardClient) GetAgentStatus(agentID string) (*Agent, error) {
	var response struct {
		APIResponse
		Data struct {
			Agent Agent `json:"agent"`
		} `json:"data"`
	}

	err := c.makeRequest("GET", fmt.Sprintf("/api/agents/%s", agentID), nil, &response)
	if err != nil {
		return nil, err
	}

	return &response.Data.Agent, nil
}

// SendHeartbeat sends a heartbeat to update agent status
func (c *DashboardClient) SendHeartbeat(agentID string, metadata map[string]interface{}) error {
	payload := map[string]interface{}{
		"status":   "ONLINE",
		"metadata": metadata,
	}

	var response APIResponse
	return c.makeRequest("POST", fmt.Sprintf("/api/agents/%s/heartbeat", agentID), payload, &response)
}

// GetPendingAssessments retrieves any pending assessments for the agent
func (c *DashboardClient) GetPendingAssessments(agentID string) ([]Assessment, error) {
	var response struct {
		APIResponse
		Data struct {
			Assessments []Assessment `json:"assessments"`
		} `json:"data"`
	}

	err := c.makeRequest("GET", fmt.Sprintf("/api/assessments?agentId=%s&status=PENDING", agentID), nil, &response)
	if err != nil {
		return nil, err
	}

	return response.Data.Assessments, nil
}

// SubmitResults submits assessment results to the dashboard
func (c *DashboardClient) SubmitResults(agentID string, results []modules.AssessmentResult, overallRisk float64) error {
	// Convert modules.AssessmentResult to API format
	apiResults := make([]map[string]interface{}, len(results))
	for i, result := range results {
		apiResults[i] = map[string]interface{}{
			"checkType":  result.CheckType,
			"resultData": result.Data,
			"riskScore":  result.RiskScore,
			"riskLevel":  result.RiskLevel,
		}
	}

	payload := map[string]interface{}{
		"results":           apiResults,
		"overallRiskScore":  overallRisk,
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
	return c.makeRequest("PUT", fmt.Sprintf("/api/assessments/%s/results", assessmentID), payload, &response)
}

// makeRequest makes an HTTP request to the dashboard API
func (c *DashboardClient) makeRequest(method, endpoint string, payload interface{}, response interface{}) error {
	url := c.baseURL + endpoint

	var body *bytes.Buffer
	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal request payload: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
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
	req.Header.Set("User-Agent", "Decian-Agent/1.0.0")

	c.logger.Debug("Making API request", map[string]interface{}{
		"method":   method,
		"url":      url,
		"headers":  req.Header,
	})

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	c.logger.Debug("API response", map[string]interface{}{
		"status_code": resp.StatusCode,
		"headers":     resp.Header,
	})

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	// Decode response
	if response != nil {
		if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}