package main

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/regclient/regclient/regclient"
	"github.com/regclient/regclient/regclient/manifest"
	"github.com/regclient/regclient/regclient/types"
	"github.com/regclient/regclient/types/platform"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/archivista"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/source"
)

const (
	apiVersion                        = "externaldata.gatekeeper.sh/v1alpha1"
	defaultArchivistaURL              = "archivista.testifysec.io"
	ProviderRequestKind  ProviderKind = "ProviderRequest"
	ProviderResponseKind ProviderKind = "ProviderResponse"
)

type ProviderKind string

type ProviderRequest struct {
	APIVersion string             `json:"apiVersion,omitempty"`
	Kind       ProviderKind       `json:"kind,omitempty"`
	Request    PolicyCheckRequest `json:"request,omitempty"`
}

type PolicyCheckRequest struct {
	// Keys contains the image references to check
	Keys []string `json:"keys,omitempty"`
	// Policy is the policy to check the images against
	Policy string `json:"policy,omitempty"`
}

type ProviderResponse struct {
	APIVersion string              `json:"apiVersion,omitempty"`
	Kind       ProviderKind        `json:"kind,omitempty"`
	Response   PolicyCheckResponse `json:"response,omitempty"`
}

type PolicyCheckResponse struct {
	Items       []PolicyCheckItem `json:"items,omitempty"`
	SystemError string            `json:"systemError,omitempty"`
}

type PolicyCheckItem struct {
	Key string `json:"key,omitempty"`
	// ImageID is the ID of the image checked
	ImageID string `json:"imageID,omitempty"`
	// URIs contains a list of evidence URIs
	URIs []string `json:"uris,omitempty"`
	// Passed indicates if the artifact passed the policy check
	Passed bool `json:"passed,omitempty"`
	// Reasons contains a list of reasons why the artifact did not pass the policy check
	Reasons []string `json:"reasons,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func main() {
	fmt.Println("starting server...")
	http.HandleFunc("/validate", validate)

	srv := &http.Server{
		Addr:              ":8090",
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}

func validate(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	if req.Method != http.MethodPost {
		sendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	// parse request body
	var policyCheckRequest PolicyCheckRequest
	err = json.Unmarshal(requestBody, &policyCheckRequest)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	ctx := req.Context()
	results := make([]externaldata.Item, 0)

	// Extract policy from the request
	policy := policyCheckRequest.Policy

	// Get public key from file
	pemPubKey, err := ioutil.ReadFile(os.Getenv("PUB_KEY"))
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to read public key file: %v", err), w)
		return
	}

	// Iterate over all keys (image refs)
	for _, imageRef := range policyCheckRequest.Keys {
		// Get ImageID for each ImageRef
		manifest, err := getManifest(imageRef)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("unable to get manifest for image %s: %v", imageRef, err), w)
			return
		}

		// Get ImageID from manifest
		imageID := manifest.GetDescriptor().Digest.String()

		// Call runVerify using the provided policy and ImageID
		policyCheckItem, err := runVerify(ctx, imageID, policy, string(pemPubKey))
		if err != nil {
			// Handle error
			// Assuming sendResponse can handle errors.
			sendResponse(nil, fmt.Sprintf("error while verifying policy: %v", err), w)
			return
		}

		results = append(results, externaldata.Item{
			Key: imageRef,
			Value: map[string]string{
				"decision":      strconv.FormatBool(policyCheckItem.Passed),
				"evidenceOID":   strings.Join(policyCheckItem.URIs, ","),
				"error":         policyCheckItem.Error,
				"failureReason": strings.Join(policyCheckItem.Reasons, ","),
			},
		})
	}
	sendResponse(&results, "", w)
}

// sendResponse sends back the response to Gatekeeper.
func sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
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

func runVerify(ctx context.Context, imageID string, policy string, pemPubKey string) (PolicyCheckItem, error) {

	var verifier cryptoutil.Verifier
	var item PolicyCheckItem

	// create a reader from the pem encoded public key
	keyReader := strings.NewReader(pemPubKey)
	verifier, err := cryptoutil.NewVerifierFromReader(keyReader)
	if err != nil {
		return item, fmt.Errorf("failed to create verifier: %w", err)
	}

	policyReader := strings.NewReader(policy)
	policyEnvelope := dsse.Envelope{}
	decoder := json.NewDecoder(policyReader)
	if err := decoder.Decode(&policyEnvelope); err != nil {
		return item, fmt.Errorf("could not unmarshal policy envelope: %w", err)
	}

	subject := cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: imageID}
	subjects := []cryptoutil.DigestSet{subject}

	var collectionSource source.Sourcer
	memSource := source.NewMemorySource()

	collectionSource = source.NewMultiSource(memSource, source.NewArchvistSource(archivista.New(defaultArchivistaURL)))

	verifiedEvidence, err := witness.Verify(
		ctx,
		policyEnvelope,
		[]cryptoutil.Verifier{verifier},
		witness.VerifyWithSubjectDigests(subjects),
		witness.VerifyWithCollectionSource(collectionSource),
	)

	if err != nil {
		return item, fmt.Errorf("failed to verify policy: %w", err)
	}

	log.Info("Verification succeeded")
	log.Info("Evidence:")
	num := 0
	var uris []string
	for _, stepEvidence := range verifiedEvidence {
		for _, e := range stepEvidence {
			log.Info(fmt.Sprintf("%d: %s", num, e.Reference))
			uris = append(uris, e.Reference)
			num++
		}
	}

	item = PolicyCheckItem{
		Key:     policy,
		ImageID: imageID,
		URIs:    uris,
		Passed:  err == nil,
		Error:   "",
	}
	if err != nil {
		item.Error = err.Error()
	}
	return item, nil
}

func getManifest(imageRef string) (manifest.Manifest, error) {
	client := regclient.NewRegClient()

	ctx := context.Background()

	r, err := types.NewRef(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create ref: %v", err)
	}

	manifest, err := client.ManifestGet(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %v", err)

	}

	//TODO: This is a workaround for multi-arch images since we dont actaully support them yet. We default to the host arch and do not support multi-arch clusters.
	if manifest.IsList() {

		plat := platform.Platform{
			Architecture: runtime.GOARCH,
			OS:           runtime.GOOS,
		}

		desc, err := manifest.GetPlatformDesc(&plat)
		if err != nil {
			return nil, err
		}

		r.Digest = desc.Digest.String()
		manifest, err = client.ManifestGet(ctx, r)
		if err != nil {
			return nil, err
		}
	}

	return manifest, nil
}
