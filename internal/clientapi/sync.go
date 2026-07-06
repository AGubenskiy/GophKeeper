package clientapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SyncItem contains an encrypted vault item transferred through the sync API.
type SyncItem struct {
	ID               string     `json:"id"`
	ServerRevision   int64      `json:"server_revision"`
	EncryptedPayload string     `json:"encrypted_payload"`
	PayloadNonce     string     `json:"payload_nonce"`
	PayloadVersion   int16      `json:"payload_version"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// PushItem contains one local encrypted item mutation.
type PushItem struct {
	ID               string     `json:"id"`
	BaseRevision     int64      `json:"base_revision"`
	EncryptedPayload string     `json:"encrypted_payload"`
	PayloadNonce     string     `json:"payload_nonce"`
	PayloadVersion   int16      `json:"payload_version"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
}

// SyncConflict describes one server-side optimistic locking conflict.
type SyncConflict struct {
	ID             string    `json:"id"`
	BaseRevision   int64     `json:"base_revision"`
	ServerRevision int64     `json:"server_revision"`
	Reason         string    `json:"reason"`
	Remote         *SyncItem `json:"remote,omitempty"`
}

// Changes contains encrypted changes returned by the server.
type Changes struct {
	Items           []SyncItem `json:"items"`
	CurrentRevision int64      `json:"current_revision"`
}

// PushResponse contains the result of a sync push.
type PushResponse struct {
	Applied         []SyncItem     `json:"applied"`
	Conflicts       []SyncConflict `json:"conflicts"`
	CurrentRevision int64          `json:"current_revision"`
}

type pushRequest struct {
	Items []PushItem `json:"items"`
}

// PullChanges returns encrypted item changes after sinceRevision.
func (c *Client) PullChanges(ctx context.Context, accessToken string, sinceRevision int64) (Changes, error) {
	if strings.TrimSpace(accessToken) == "" {
		return Changes{}, errors.New("access token is required")
	}
	if sinceRevision < 0 {
		return Changes{}, errors.New("since revision must be non-negative")
	}

	endpoint := c.endpoint("/api/v1/sync/changes")
	query := url.Values{}
	query.Set("since_revision", strconv.FormatInt(sinceRevision, 10))
	endpoint.RawQuery = query.Encode()

	var response Changes
	if err := c.doWithToken(ctx, http.MethodGet, endpoint.String(), accessToken, nil, http.StatusOK, &response); err != nil {
		return Changes{}, err
	}
	return response, nil
}

// PushChanges sends local encrypted item mutations to the server.
func (c *Client) PushChanges(ctx context.Context, accessToken string, items []PushItem) (PushResponse, error) {
	if strings.TrimSpace(accessToken) == "" {
		return PushResponse{}, errors.New("access token is required")
	}
	if items == nil {
		items = []PushItem{}
	}

	var response PushResponse
	if err := c.doWithToken(ctx, http.MethodPost, c.endpoint("/api/v1/sync/push").String(), accessToken, pushRequest{Items: items}, http.StatusOK, &response); err != nil {
		return PushResponse{}, fmt.Errorf("push changes: %w", err)
	}
	return response, nil
}
