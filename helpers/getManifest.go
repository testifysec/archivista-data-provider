package helpers

import (
	"context"
	"fmt"
	"runtime"

	"github.com/regclient/regclient/regclient"
	"github.com/regclient/regclient/regclient/types"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/platform"
)

func GetManifest(imageRef string) (manifest.Manifest, error) {
	client := regclient.NewRegClient()

	ctx := context.Background()

	r, err := types.NewRef(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create ref: %v", err)
	}

	manifest, err := client.ManifestGet(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %v", err)

	}

	//TODO: This is a workaround for multi-arch images since we dont actaully support them yet. We default to the host arch and do not support multi-arch clusters.
	if manifest.IsList() {

		plat := platform.Platform{
			Architecture: runtime.GOARCH,
			OS:           runtime.GOOS,
		}

		desc, err := manifest.GetPlatformDesc(&plat)
		if err != nil {
			return nil, err
		}

		r.Digest = desc.Digest.String()
		manifest, err = client.ManifestGet(ctx, r)
		if err != nil {
			return nil, err
		}
	}

	return manifest, nil
}
