package helpers

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/testifysec/archivista-gatekeeper-provider/gatekeeper"
	"github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/archivista"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/source"
)

func RunVerify(ctx context.Context, imageID string, policy string, pemPubKey string, ac *archivista.Client) (gatekeeper.Item, error) {

	var verifier cryptoutil.Verifier
	var item gatekeeper.Item

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

	collectionSource = source.NewMultiSource(memSource, source.NewArchvistSource(ac))

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

	item = gatekeeper.Item{
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
