package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "container-image-provider",
}

func Execute() error {
	return rootCmd.Execute()
}
