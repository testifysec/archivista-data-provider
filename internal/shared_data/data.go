package shareddata

import (
	"errors"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/policy"
)

var (
	policyLock    sync.RWMutex
	publicKeyLock sync.RWMutex
	policies      map[string]dsse.Envelope
	publicKeys    map[string]policy.PublicKey
)

func init() {
	policies = make(map[string]dsse.Envelope, 0)
	publicKeys = make(map[string]policy.PublicKey, 0)
}

func UsePolicy(name string, doWork func(dsse.Envelope)) error {
	policyLock.RLock()
	defer policyLock.RUnlock()

	if p, ok := policies[name]; ok {
		doWork(p)
	} else {
		return errors.New("policy not found")
	}

	return nil
}

func UsePublicKey(name string, doWork func(policy.PublicKey)) error {
	publicKeyLock.RLock()
	defer publicKeyLock.RUnlock()

	if p, ok := publicKeys[name]; ok {
		doWork(p)
	} else {
		return errors.New("public key not found")
	}

	return nil
}

// TODO: Can we do this without returning results?
func UsePoliciesAndPublicKeys(doWork func(policies map[string]dsse.Envelope, publicKeys map[string]policy.PublicKey) (results *[]externaldata.Item)) *[]externaldata.Item {
	policyLock.RLock()
	defer policyLock.RUnlock()

	publicKeyLock.RLock()
	defer publicKeyLock.RUnlock()

	return doWork(policies, publicKeys)
}

func AddPolicy(name string, p dsse.Envelope) {
	policyLock.Lock()
	defer policyLock.Unlock()

	policies[name] = p
}

func AddPublicKey(name string, p policy.PublicKey) {
	publicKeyLock.Lock()
	defer publicKeyLock.Unlock()

	publicKeys[name] = p
}

func RemovePolicy(name string) {
	policyLock.Lock()
	defer policyLock.Unlock()

	delete(policies, name)
}

func RemovePublicKey(name string) {
	publicKeyLock.Lock()
	defer publicKeyLock.Unlock()

	delete(publicKeys, name)
}
