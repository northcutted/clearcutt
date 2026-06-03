package catalogbuild

import (
	"regexp"
	"sort"
	"strings"
)

// -- SPDX SBOM transforms ----------------------------------------------------

// SPDX input model (only the fields gather-catalog.mjs reads).
type spdxDoc struct {
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPkg          `json:"packages"`
	Files             []spdxFile         `json:"files"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Creators []string `json:"creators"`
	Created  string   `json:"created"`
}

type spdxPkg struct {
	SPDXID                string            `json:"SPDXID"`
	Name                  string            `json:"name"`
	VersionInfo           string            `json:"versionInfo"`
	Supplier              string            `json:"supplier"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	LicenseConcluded      string            `json:"licenseConcluded"`
	SourceInfo            string            `json:"sourceInfo"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs"`
	Checksums             []spdxChecksum    `json:"checksums"`
}

type spdxExternalRef struct {
	ReferenceType    string `json:"referenceType"`
	ReferenceLocator string `json:"referenceLocator"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxFile struct {
	SPDXID  string `json:"SPDXID"`
	Comment string `json:"comment"`
}

type spdxRelationship struct {
	RelationshipType   string `json:"relationshipType"`
	SpdxElementID      string `json:"spdxElementId"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

// spdxPackageOut mirrors the compacted package the Node producer emits (explicit
// nulls, fixed key order, empty cpes array rather than null).
type spdxPackageOut struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Purl         *string  `json:"purl"`
	Cpes         []string `json:"cpes"`
	License      string   `json:"license"`
	Supplier     string   `json:"supplier"`
	NixStorePath *string  `json:"nixStorePath"`
	SpdxID       string   `json:"spdxId"`
	LayerDigest  *string  `json:"layerDigest"`
}

var nixStorePathRe = regexp.MustCompile(`(/nix/store/[^\s]+)`)

func extractNixStorePath(sourceInfo string) *string {
	if sourceInfo == "" {
		return nil
	}
	if m := nixStorePathRe.FindString(sourceInfo); m != "" {
		return &m
	}
	return nil
}

func pickLicense(pkg spdxPkg) string {
	for _, c := range []string{pkg.LicenseDeclared, pkg.LicenseConcluded} {
		if c != "" && c != "NOASSERTION" {
			return c
		}
	}
	return "NOASSERTION"
}

func mapPackageIDToLayerDigest(spdx spdxDoc) map[string]string {
	fileToLayer := map[string]string{}
	for _, f := range spdx.Files {
		if strings.HasPrefix(f.Comment, "layerID: ") {
			fileToLayer[f.SPDXID] = strings.TrimSpace(strings.TrimPrefix(f.Comment, "layerID: "))
		}
	}
	packageToLayer := map[string]string{}
	for _, r := range spdx.Relationships {
		if r.RelationshipType == "OTHER" && r.SpdxElementID != "" && r.RelatedSpdxElement != "" {
			if digest, ok := fileToLayer[r.RelatedSpdxElement]; ok {
				packageToLayer[r.SpdxElementID] = digest
			}
		}
	}
	return packageToLayer
}

func compactPackages(spdx spdxDoc) []spdxPackageOut {
	packageToLayer := mapPackageIDToLayerDigest(spdx)
	items := []spdxPackageOut{}
	for _, p := range spdx.Packages {
		if p.PrimaryPackagePurpose == "CONTAINER" {
			continue
		}
		cpes := []string{}
		var purl *string
		for _, ref := range p.ExternalRefs {
			switch ref.ReferenceType {
			case "cpe23Type":
				cpes = append(cpes, ref.ReferenceLocator)
			case "purl":
				if purl == nil {
					loc := ref.ReferenceLocator
					purl = &loc
				}
			}
		}
		supplier := p.Supplier
		if supplier == "" {
			supplier = "NOASSERTION"
		}
		var layerDigest *string
		if d, ok := packageToLayer[p.SPDXID]; ok {
			layerDigest = &d
		}
		items = append(items, spdxPackageOut{
			Name:         p.Name,
			Version:      p.VersionInfo,
			Purl:         purl,
			Cpes:         cpes,
			License:      pickLicense(p),
			Supplier:     supplier,
			NixStorePath: extractNixStorePath(p.SourceInfo),
			SpdxID:       p.SPDXID,
			LayerDigest:  layerDigest,
		})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func rootDigest(spdx spdxDoc) *string {
	for _, p := range spdx.Packages {
		if p.PrimaryPackagePurpose != "CONTAINER" {
			continue
		}
		for _, c := range p.Checksums {
			if c.Algorithm == "SHA256" {
				d := "sha256:" + c.ChecksumValue
				return &d
			}
		}
		if strings.HasPrefix(p.VersionInfo, "sha256:") {
			v := p.VersionInfo
			return &v
		}
		return nil
	}
	return nil
}
