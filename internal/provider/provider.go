package provider

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/testifysec/archivista-data-provider/pkg/handler"
	"github.com/testifysec/archivista-data-provider/pkg/utils"
	"github.com/testifysec/archivista-data-provider/pkg/utils/certs"
	"github.com/testifysec/go-witness/archivista"
	"k8s.io/klog/v2"
	"net/http"
	"os"
	"time"
)

const (
	// TODO: Fix timeout handling.
	timeout           = 300 * time.Second
	defaultPort       = 8090
	apiVersion        = "externaldata.gatekeeper.sh/v1alpha1"
	defaultCertFile   = "/etc/ssl/certs/server.crt"
	defaultKeyFile    = "/etc/ssl/certs/server.key"
	defaultCaCertFile = "/usr/local/tls/client-ca/ca.crt"
)

var (
	certFile     string
	keyFile      string
	clientCAFile string
	port         int
)

// Provider is used for running the gatekeeper provider. Provider will verify images when sent requests to do so by Gatekeeper.
type Provider struct {
	// log is the Controller logger.
	log logr.Logger

	ctx context.Context

	tls TLS

	watchers map[string]*utils.Watcher
}

type TLS struct {
	certificate *tls.Certificate
	key         *crypto.PrivateKey
	clientCAs   *x509.CertPool
}

// New constructs a new Provider instance.
func New() (*Provider, error) {
	p := &Provider{
		ctx:      context.Background(),
		watchers: map[string]*utils.Watcher{},
	}

	klog.InitFlags(nil)
	flag.StringVar(&certFile, "tls-cert-file", "", "path to the file containing the TLS certificate for the provider")
	flag.StringVar(&keyFile, "tls-key-file", "", "path to the file containing the TLS private key for the provider")
	flag.StringVar(&clientCAFile, "client-ca-file", defaultCaCertFile, "path to client CA certificate")
	flag.IntVar(&port, "port", defaultPort, "Port for the server to listen on")
	flag.Parse()

	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("tls certificate and key path is required for the provider")
	}

	f, err := os.ReadFile(certFile)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("reading client certificate file from path %s", certFile))
	}

	p.tls.certificate, err = certs.ParseCert(f)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("faild to parse certificate"))
	}

	w, err := utils.NewWatcher(p.ctx, certFile, func() error {
		f, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}

		p.tls.certificate, err = certs.ParseCert(f)
		if err != nil {
			return errors.Join(err, fmt.Errorf("faild to parse certificate"))
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	p.watchers["cert"] = w

	f, err = os.ReadFile(keyFile)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("reading client private key from path %s", keyFile))
	}

	p.tls.key, err = certs.ParseKey(f)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("faild to parse certificate key"))
	}

	w, err = utils.NewWatcher(p.ctx, keyFile, func() error {
		f, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}

		p.tls.key, err = certs.ParseKey(f)
		if err != nil {
			return errors.Join(err, fmt.Errorf("faild to parse certificate key"))
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	p.watchers["key"] = w

	// For now having the CA cert field populated is going to be optional. There might be other ways that people are mounting in the CA cert.
	if clientCAFile != "" {
		cacert, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, errors.Join(err, fmt.Errorf("reading gatekeeper CA certificate file from path %s", clientCAFile))
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(cacert) {
			return nil, fmt.Errorf("Failed to add Gatekeeper CA Certificate to pool")
		}

		p.tls.clientCAs = certPool

	} else {
		// TODO: Logically, I don't really see why we shouldn't be trying to hot-reload the system cert pool.
		// I am not sure at the moment how this would work however.
		rootCAs, _ := x509.SystemCertPool()
		if err != nil {
			return nil, errors.Join(err, fmt.Errorf("failed to get system certificate pool"))
		}
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		p.tls.clientCAs = rootCAs
	}

	return p, nil
}

func (p *Provider) Start() error {
	fmt.Println("starting server...")

	ac := archivista.New("https://archivista.testifysec.io")
	vh := handler.NewValidateHandler(ac)

	mux := http.NewServeMux()
	mux.HandleFunc("/", vh.Handler)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientCAs:  p.tls.clientCAs,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			var certificate tls.Certificate
			certificate.Certificate = p.tls.certificate.Certificate
			certificate.PrivateKey = *p.tls.key
			return &certificate, nil
		},
	}

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: time.Duration(5) * time.Second,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		return err
	}

	return nil
}
