package main

import (
	"os"

	"github.com/testifysec/archivista-data-provider/internal/provider"
	"k8s.io/klog/v2"
)

func main() {
	c, err := provider.New()
	if err != nil {
		klog.ErrorS(err, "unable to initialize archivista data provider server")
		os.Exit(1)
	}

	klog.Info("starting archivista data provider...")

	c.Start()
}
