package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/testifysec/archivista-data-provider/pkg/handler"
	"github.com/testifysec/archivista-data-provider/pkg/manager"
	"github.com/testifysec/go-witness/archivista"
	"github.com/testifysec/go-witness/cryptoutil"

	"k8s.io/klog/v2"
)

const (
	// TODO: Fix timeout handling.
	timeout     = 300 * time.Second
	defaultPort = 8090

	certName = "tls.crt"
	keyName  = "tls.key"
)

var (
	certDir       string
	clientCAFile  string
	archivistaUrl string
	port          int
)

func init() {
	klog.InitFlags(nil)
	flag.StringVar(&certDir, "cert-dir", "", "path to directory containing TLS certificates")
	flag.StringVar(&clientCAFile, "client-ca-file", "", "path to client CA certificate")
	flag.IntVar(&port, "port", defaultPort, "Port for the server to listen on")
	flag.StringVar(&archivistaUrl, "archivista-url", "https://archivista.testifysec.io", "url to the archivista instance to query")
	flag.Parse()
}

func main() {
	if _, err := url.ParseRequestURI(archivistaUrl); err != nil {
		klog.ErrorS(err, "invalid archivista url", "archivista-url", archivistaUrl)
		os.Exit(1)
	}

	ac := archivista.New(archivistaUrl)
	signer, err := loadSigner(filepath.Join(certDir, keyName), filepath.Join(certDir, certName))
	if err != nil {
		klog.ErrorS(err, "failed to load signer")
		os.Exit(1)
	}

	vh := handler.NewValidateHandler(ac, signer)

	mux := http.NewServeMux()
	mux.HandleFunc("/", vh.Handler)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: time.Duration(5) * time.Second,
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if clientCAFile != "" {
		klog.InfoS("loading Gatekeeper's CA certificate", "clientCAFile", clientCAFile)
		caCert, err := os.ReadFile(clientCAFile)
		if err != nil {
			klog.ErrorS(err, "unable to load Gatekeeper's CA certificate", "clientCAFile", clientCAFile)
			os.Exit(1)
		}

		clientCAs := x509.NewCertPool()
		clientCAs.AppendCertsFromPEM(caCert)

		config.ClientCAs = clientCAs
		config.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLSConfig = config
	}

	if certDir != "" {
		certFile := filepath.Join(certDir, certName)
		keyFile := filepath.Join(certDir, keyName)

		klog.Info("start archivista controller manager")
		go manager.StartManager()

		klog.InfoS("starting archivista data provider server", "port", port, "certFile", certFile, "keyFile", keyFile)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			klog.ErrorS(err, "unable to start archivista data provider server")
			os.Exit(1)
		}
	} else {
		klog.Error("TLS certificates are not provided, the server will not be started")
		os.Exit(1)
	}
}

func loadSigner(keyFilePath, certFilePath string) (cryptoutil.Signer, error) {
	keyFile, err := os.Open(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("couldn't load key: %w", err)
	}

	defer keyFile.Close()
	certFile, err := os.Open(certFilePath)
	if err != nil {
		return nil, fmt.Errorf("couldn't load cert: %w", err)
	}

	certBytes, err := io.ReadAll(certFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read cert: %w", err)
	}

	cert, err := cryptoutil.TryParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse cert: %w", err)
	}

	defer certFile.Close()
	return cryptoutil.NewSignerFromReader(keyFile, cryptoutil.SignWithCertificate(cert))
}
