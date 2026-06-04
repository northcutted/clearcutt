package catalogbuild

import (
	"os"
	"strings"
)

func spdxTool(spdx spdxDoc) string {
	for _, creator := range spdx.CreationInfo.Creators {
		if strings.HasPrefix(creator, "Tool:") {
			tool := strings.TrimSpace(strings.TrimPrefix(creator, "Tool:"))
			if tool != "" {
				return tool
			}
		}
	}
	return "syft"
}

func readCachedSBOM(cachePath string, mustRefresh bool) ([]byte, bool) {
	if mustRefresh || cachePath == "" {
		return nil, false
	}
	buf, err := os.ReadFile(cachePath)
	return buf, err == nil
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func catalogArchAssets(assets []Asset, target, suffix string) []Asset {
	out := []Asset{}
	for _, asset := range assets {
		if (strings.HasPrefix(asset.Name, target+"-amd64.") || strings.HasPrefix(asset.Name, target+"-arm64.")) && strings.HasSuffix(asset.Name, suffix) {
			out = append(out, asset)
		}
	}
	return out
}

func catalogAssetsNamed(assets []Asset, name string) []Asset {
	out := []Asset{}
	for _, asset := range assets {
		if asset.Name == name {
			out = append(out, asset)
		}
	}
	return out
}

func catalogAssetNamed(assets []Asset, name string) *Asset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

func assetURL(asset *Asset) *string {
	if asset == nil || asset.URL == "" {
		return nil
	}
	url := asset.URL
	return &url
}

func assetURLsFromAssets(sbomAssets, testAssets []Asset, provAsset, digestAsset *Asset) gatherAssetURLs {
	sbomURLs := map[string]string{}
	for _, asset := range sbomAssets {
		sbomURLs[guessArchFromAsset(asset.Name, nil)] = asset.URL
	}
	testURLs := map[string]string{}
	for _, asset := range testAssets {
		testURLs[guessArchFromAsset(asset.Name, nil)] = asset.URL
	}
	return gatherAssetURLs{
		SBOM:        sbomURLs,
		Provenance:  assetURL(provAsset),
		TestResults: testURLs,
		Digest:      assetURL(digestAsset),
	}
}

func totalImageSize(architectures []gatherArchPayload) *int64 {
	var total int64
	for _, arch := range architectures {
		if arch.ImageSize != nil {
			total += *arch.ImageSize
		}
	}
	if total == 0 {
		return nil
	}
	return &total
}

func RefreshTagSet(releases []Release, forceAll bool, forceTags string) map[string]bool {
	out := map[string]bool{}
	if forceAll {
		for _, rel := range releases {
			out[rel.Tag] = true
		}
		return out
	}
	if forceTags != "" {
		for _, tag := range strings.Split(forceTags, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				out[tag] = true
			}
		}
		return out
	}
	for _, rel := range releases {
		if !rel.Prerelease {
			out[rel.Tag] = true
			return out
		}
	}
	if len(releases) > 0 {
		out[releases[0].Tag] = true
	}
	return out
}
