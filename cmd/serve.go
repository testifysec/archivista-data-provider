package cmd

import (
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"github.com/testifysec/archivista-gatekeeper-provider/httpHandlers"
	"github.com/testifysec/go-witness/archivista"
)

var (
	serverCmd = &cobra.Command{
		Use:   "serve",
		Short: "Run the server",
		Run:   runServer,
	}

	archivistaURL string
)

func runServer(cmd *cobra.Command, args []string) {
	archivistaClient := archivista.New(archivistaURL)

	validateHandler := httpHandlers.NewValidateHandler(archivistaClient)

	http.HandleFunc("/gatekeeper/validate", validateHandler.Validate)

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

func init() {
	serverCmd.PersistentFlags().StringVar(&archivistaURL, "archivista-url", "archivista.testifysec.io", "URL of the Archivista server")
	rootCmd.AddCommand(serverCmd)
}
