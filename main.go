package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/testifysec/archivista-data-provider/pkg/handler"
	"github.com/testifysec/archivista-data-provider/pkg/manager"
	"github.com/testifysec/go-witness/archivista"

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
	certDir      string
	clientCAFile string
	port         int
)

func init() {
	klog.InitFlags(nil)
	flag.StringVar(&certDir, "cert-dir", "", "path to directory containing TLS certificates")
	flag.StringVar(&clientCAFile, "client-ca-file", "", "path to client CA certificate")
	flag.IntVar(&port, "port", defaultPort, "Port for the server to listen on")
	flag.Parse()
}

func main() {
	ac := archivista.New("https://archivista.testifysec.io")
	vh := handler.NewValidateHandler(ac)

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
