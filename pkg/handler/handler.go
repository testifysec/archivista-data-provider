package handler

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/gatekeeper-external-data-provider/pkg/utils"
	"github.com/regclient/regclient"
	rcManifest "github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"
	"github.com/sirupsen/logrus"
	shareddata "github.com/testifysec/archivista-data-provider/internal/shared_data"
	"github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/archivista"

	// Work around for initialization of attestation plugins.
	_ "github.com/testifysec/go-witness/attestation/material"
	_ "github.com/testifysec/go-witness/attestation/product"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/policy"
	"github.com/testifysec/go-witness/source"
	"k8s.io/klog/v2"
)

type ValidateHandler struct {
	archivista *archivista.Client
}

func NewValidateHandler(archivista *archivista.Client) *ValidateHandler {
	return &ValidateHandler{
		archivista: archivista,
	}
}

func (vh ValidateHandler) Handler(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	if req.Method != http.MethodPost {
		utils.SendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	klog.InfoS("received request", "body", requestBody)

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	rc := regclient.New()
	// iterate over all keys
	for _, rKey := range providerRequest.Request.Keys {
		// Providers should add a caching mechanism to avoid extra calls to external data sources.
		// TODO: Determine time of cache length for policy decision

		image, err := ref.New(rKey)
		if err != nil {
			utils.SendResponse(nil, fmt.Sprintf("unable to create ref for image %s: %v", rKey, err), w)
			return
		}

		if image.Digest == "" {
			klog.Warning("Image with tag was used, this is unsafe! ", "image", rKey)
		}

		// TODO: add support for multi-arch images
		var digest string
		manifest, err := rc.ManifestGet(req.Context(), image)
		if err != nil {
			utils.SendResponse(nil, fmt.Sprintf("unable to get manifest for image %s: %v", rKey, err), w)
			continue
		}
		if manifest.IsList() {
			klog.Info("Multi-platform image detected, looking up digest for current platform")
			plat := platform.Platform{
				Architecture: runtime.GOARCH,
				OS:           runtime.GOOS,
			}

			desc, err := rcManifest.GetPlatformDesc(manifest, &plat)
			if err != nil {
				utils.SendResponse(nil, fmt.Sprintf("unable to get platform description for image %s: %v", rKey, err), w)
				continue
			}

			digest = desc.Digest.String()
		} else {
			if imager, ok := manifest.(rcManifest.Imager); ok {
				config, err := imager.GetConfig()
				if err != nil {
					utils.SendResponse(nil, fmt.Sprintf("unable to get config digest for image %s: %v", rKey, err), w)
					continue
				}
				klog.Info("Using config digest")
				digest = config.Digest.String()
			} else {
				utils.SendResponse(nil, fmt.Sprintf("unable to get config digest for image %s: %v", rKey, err), w)
				continue
			}
		}

		digest = strings.TrimPrefix(digest, "sha256:")
		klog.Info("Using resolved digest ", "digest", digest)

		// Do verify
		results := shareddata.UsePoliciesAndPublicKeys(func(policies map[string]dsse.Envelope, keys map[string]policy.PublicKey) (results *[]externaldata.Item) {
			policyResults := make([]externaldata.Item, 0)

			for policyName, policyEnv := range policies {
				klog.Info("Verifying policy ", "name", policyName)

				// Currently only support one signature per policy
				policyKey := policyEnv.Signatures[0]

				key, found := keys[policyKey.KeyID]
				if !found {
					klog.Error("unable to get policy key", "key", policyKey.KeyID)
					policyResults = append(policyResults, externaldata.Item{
						Key:   rKey,
						Error: "Policy verification failed: no public key",
					})
					continue
				}

				// create a reader from the pem encoded public key
				keyReader := bytes.NewReader(key.Key)
				verifier, err := cryptoutil.NewVerifierFromReader(keyReader)
				if err != nil {
					klog.Error(err, "failed to create verifier")
				}

				subject := cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: digest}
				subjects := []cryptoutil.DigestSet{subject}

				var collectionSource source.Sourcer
				memSource := source.NewMemorySource()

				collectionSource = source.NewMultiSource(memSource, source.NewArchvistSource(vh.archivista))

				fmt.Printf("Verifying policy %s\n", policyName)
				fmt.Printf("Verifying policy %v\n", policyEnv)
				fmt.Printf("Verifying subjects %s\n", digest)
				fmt.Printf("Verifying collection source %v\n", collectionSource)
				fmt.Printf("Verifying archivista %v\n", *vh.archivista)

				logger := logrus.New()
				logger.Out = os.Stdout
				log.SetLogger(logger)

				verifiedEvidence, err := witness.Verify(
					req.Context(),
					policyEnv,
					[]cryptoutil.Verifier{verifier},
					witness.VerifyWithSubjectDigests(subjects),
					witness.VerifyWithCollectionSource(collectionSource),
				)
				if err != nil {
					klog.Error(err, "failed to verify policy", "name", policyName)
					policyResults = append(policyResults, externaldata.Item{
						Key:   rKey,
						Error: "Policy verification failed: " + err.Error(),
					})
					continue
				}

				klog.Info("Verification succeeded")
				klog.Info("Evidence:")
				num := 0
				var uris []string
				for _, stepEvidence := range verifiedEvidence {
					for i := range stepEvidence {
						klog.Info(fmt.Sprintf("%d: %s", num, stepEvidence[i].Reference))
						uris = append(uris, stepEvidence[i].Reference)
						num++
					}
				}

				policyResults = append(policyResults, externaldata.Item{
					Key: rKey,
					Value: map[string]string{
						"PolicyName": policyName,
						"ImageID":    digest,
						"URIs":       strings.Join(uris, ""),
						"Passed":     strconv.FormatBool(true),
					},
				})
			}

			return &policyResults
		})

		utils.SendResponse(results, "", w)
	}
}
