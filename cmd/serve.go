package cmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/testifysec/archivista-data-provider/handlers"
	"github.com/testifysec/go-witness/archivista"
)

var (
	serverCmd = &cobra.Command{
		Use:   "serve",
		Short: "Run the server",
		RunE:  runServer,
	}

	archivistaURL string
	serverAddress string
	serverPort    string
	spiffeSocket  string
	certFile      string
	keyFile       string
)

func runServer(cmd *cobra.Command, args []string) error {
	archivistaClient := archivista.New(archivistaURL)
	gatekeeperHandler := handlers.NewValidateHandler(archivistaClient)
	http.HandleFunc("/gatekeeper/validate", gatekeeperHandler.Validate)

	addr := fmt.Sprintf("%s:%s", serverAddress, serverPort)
	server := &http.Server{
		Addr:              addr,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if spiffeSocket != "" {
		ctx := cmd.Context()
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+spiffeSocket)))
		if err != nil {
			return fmt.Errorf("creating X509Source: %w", err)
		}
		defer source.Close()

		tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
		listener, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("starting TLS listener: %w", err)
		}
		defer listener.Close()

		if err := server.Serve(listener); err != nil {
			return fmt.Errorf("server exited: %w", err)
		}

	} else if certFile != "" && keyFile != "" {
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			return fmt.Errorf("server exited: %w", err)
		}
	} else {
		if err := server.ListenAndServe(); err != nil {
			return fmt.Errorf("server exited: %w", err)
		}
	}
	return nil
}

func init() {
	serverCmd.PersistentFlags().StringVar(&archivistaURL, "archivista-url", "archivista.testifysec.io", "URL of the Archivista server")
	serverCmd.PersistentFlags().StringVar(&serverAddress, "address", "localhost", "Address for the server to listen on")
	serverCmd.PersistentFlags().StringVar(&serverPort, "port", "8090", "Port for the server to listen on")
	serverCmd.PersistentFlags().StringVar(&spiffeSocket, "spiffe-socket", "", "SPIFFE socket to obtain SVID")
	serverCmd.PersistentFlags().StringVar(&certFile, "cert", "", "Certificate file for TLS termination")
	serverCmd.PersistentFlags().StringVar(&keyFile, "key", "", "Key file for TLS termination")
	rootCmd.AddCommand(serverCmd)
}
