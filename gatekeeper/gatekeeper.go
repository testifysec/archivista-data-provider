package gatekeeper

import (
	"encoding/json"
	"net/http"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
)

type ProviderKind string

type Response struct {
	Items       []Item `json:"items,omitempty"`
	SystemError string `json:"systemError,omitempty"`
}
type Item struct {
	Key     string   `json:"key,omitempty"`
	ImageID string   `json:"imageID,omitempty"`
	URIs    []string `json:"uris,omitempty"`
	Passed  bool     `json:"passed,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func SendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}
	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

type Request struct {
	Keys   []string `json:"keys,omitempty"`
	Policy string   `json:"policy,omitempty"`
}
