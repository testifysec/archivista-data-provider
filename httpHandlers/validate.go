package httpHandlers

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/testifysec/archivista-gatekeeper-provider/gatekeeper"
	"github.com/testifysec/archivista-gatekeeper-provider/helpers"
	"github.com/testifysec/go-witness/archivista"
)

type ValidateHandler struct {
	archivista *archivista.Client
}

func NewValidateHandler(archivista *archivista.Client) *ValidateHandler {
	return &ValidateHandler{
		archivista: archivista,
	}
}
func (h *ValidateHandler) Validate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		gatekeeper.SendResponse(nil, "only POST is allowed", w)
		return
	}
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		gatekeeper.SendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}
	var gatekeeperRequest gatekeeper.Request
	err = json.Unmarshal(requestBody, &gatekeeperRequest)
	if err != nil {
		gatekeeper.SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}
	ctx := req.Context()
	results := make([]externaldata.Item, 0)
	policy := gatekeeperRequest.Policy
	pemPubKey, err := ioutil.ReadFile(os.Getenv("PUB_KEY"))
	if err != nil {
		gatekeeper.SendResponse(nil, fmt.Sprintf("unable to read public key file: %v", err), w)
		return
	}
	for _, imageRef := range gatekeeperRequest.Keys {
		manifest, err := helpers.GetManifest(imageRef)
		if err != nil {
			gatekeeper.SendResponse(nil, fmt.Sprintf("unable to get manifest for image %s: %v", imageRef, err), w)
			return
		}
		imageID := manifest.GetDescriptor().Digest.String()
		gatekeeperItem, err := helpers.RunVerify(ctx, imageID, policy, string(pemPubKey), h.archivista)
		if err != nil {
			gatekeeper.SendResponse(nil, fmt.Sprintf("error while verifying policy: %v", err), w)
			return
		}
		results = append(results, externaldata.Item{
			Key: imageRef,
			Value: map[string]string{
				"decision":      strconv.FormatBool(gatekeeperItem.Passed),
				"evidenceOID":   strings.Join(gatekeeperItem.URIs, ","),
				"error":         gatekeeperItem.Error,
				"failureReason": strings.Join(gatekeeperItem.Reasons, ","),
			},
		})
	}
	gatekeeper.SendResponse(&results, "", w)
}
