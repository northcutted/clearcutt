package estateverify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// reproductionPredicateFor is what clearcutt-factory verify --attest signs.
func reproductionPredicateFor(method, image, digest, fromType, fromSHA256 string) map[string]any {
	return map[string]any{
		"method": method, "image": image, "digest": digest,
		"from":     map[string]any{"predicateType": fromType, "digest": map[string]string{"sha256": fromSHA256}},
		"factory":  map[string]string{"version": "v0.2.0"},
		"buildkit": "moby/buildkit:v0.33.1@sha256:" + strings.Repeat("b", 64),
		"builder": map[string]string{
			"id":       "https://github.com/acme/images/actions/runs/123/attempts/1",
			"workflow": "acme/images/.github/workflows/images.yml@refs/heads/main", "job": "reproduce",
			"runner": "github-hosted", "os": "linux", "arch": "amd64",
		},
		"reproducedAt": "2026-10-05T06:41:09Z",
	}
}

// statementIn is the in-toto statement (the DSSE payload) a bundle signs.
func statementIn(t *testing.T, bundle []byte) []byte {
	t.Helper()
	f, err := decodeBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return f.Statement
}

type recordingReproducer struct {
	mu   sync.Mutex
	refs []string
}

func (r *recordingReproducer) Reproduce(_ context.Context, ref string, _ report.Signer) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refs = append(r.refs, ref)
	return "", errors.New("buildkit: no container runtime")
}

// TestReproductionAttestations (#70): a clearcutt-factory reproduction
// attestation counts, without rebuilding, only when cosign verified it
// against the image signers, it is about the image, and it was made from a
// recipe or rebase record verified on the same image.
func TestReproductionAttestations(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	evil := fulcioCert(t, evilSigner, ghIssuer)

	// pushBuilt pushes an image with a recipe signed by recipeCert and
	// returns its digest and the recipe's statement digest.
	descs := map[string]v1.Descriptor{}
	pushBuilt := func(name, recipeCert string) (string, string) {
		idx := pushIndex(t, host+"/"+name+":1", nil, built, nil)
		d := descriptorOf(t, idx)
		descs[name] = d
		attach(t, host+"/"+name, d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
		recipe := bundleJSON(t, PredicateRecipe, d.Digest.String(), imageRecipePredicate(host+"/base:latest", "sha256:"+strings.Repeat("e", 64)), recipeCert)
		attach(t, host+"/"+name, d, recipe)
		return d.Digest.String(), statementDigest(statementIn(t, recipe))
	}
	attest := func(name, digest string, predicate map[string]any, cert string) {
		attach(t, host+"/"+name, descs[name], bundleJSON(t, PredicateReproduction, descs[name].Digest.String(), predicate, cert))
	}

	tools, toolsRecipe := pushBuilt("tools", ours)
	attest("tools", tools, reproductionPredicateFor("recipe-rebuild", host+"/tools@"+tools, tools, PredicateRecipe, toolsRecipe), ours)

	// rebased carries a rebase record and a repeat of that rebase.
	rb := pushIndex(t, host+"/rebased:1", nil, built, nil)
	rbd := descriptorOf(t, rb)
	descs["rebased"] = rbd
	attach(t, host+"/rebased", rbd, bundleJSON(t, PredicateCosignSign, rbd.Digest.String(), map[string]any{}, ours))
	rebaseRecord := bundleJSON(t, PredicateRebase, rbd.Digest.String(), map[string]any{"factory": map[string]string{"version": "v0.2.0"}, "image": host + "/tools@" + tools}, ours)
	attach(t, host+"/rebased", rbd, rebaseRecord)
	rebased := rbd.Digest.String()
	attest("rebased", rebased, reproductionPredicateFor("rebase-repeat", host+"/rebased@"+rebased, rebased, PredicateRebase, statementDigest(statementIn(t, rebaseRecord))), ours)

	// Each of these has an attestation that mustn't count.
	forged, forgedRecipe := pushBuilt("forged", ours)
	attest("forged", forged, reproductionPredicateFor("recipe-rebuild", host+"/forged@"+forged, forged, PredicateRecipe, forgedRecipe), evil)
	borrowed, _ := pushBuilt("borrowed", ours)
	attest("borrowed", borrowed, reproductionPredicateFor("recipe-rebuild", host+"/borrowed@"+borrowed, borrowed, PredicateRecipe, toolsRecipe), ours)
	otherDigest, otherRecipe := pushBuilt("otherdigest", ours)
	attest("otherdigest", otherDigest, reproductionPredicateFor("recipe-rebuild", host+"/otherdigest@"+otherDigest, tools, PredicateRecipe, otherRecipe), ours)
	wrongMethod, wrongMethodRecipe := pushBuilt("wrongmethod", ours)
	attest("wrongmethod", wrongMethod, reproductionPredicateFor("rebase-repeat", host+"/wrongmethod@"+wrongMethod, wrongMethod, PredicateRecipe, wrongMethodRecipe), ours)
	// Its recipe was signed by a stranger, so nothing can be reproduced from it.
	strangers, strangersRecipe := pushBuilt("strangers", evil)
	attest("strangers", strangers, reproductionPredicateFor("recipe-rebuild", host+"/strangers@"+strangers, strangers, PredicateRecipe, strangersRecipe), ours)

	names := []string{"tools", "rebased", "forged", "borrowed", "otherdigest", "wrongmethod", "strangers"}
	var refs []string
	for _, n := range names {
		refs = append(refs, n+":1")
	}
	verifier := acmeVerifier()
	run := func(reproduce bool, rep Reproducer) map[string]report.Image {
		t.Helper()
		r, err := Build(context.Background(), observe(t, host, refs...), Options{
			Name: "attested", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: verifier, Platforms: []string{"linux/amd64"}, Reproducer: rep,
			Policy: report.Policy{Required: []string{"signature"}, TrustedSigners: verifier.Signers, Reproduce: reproduce},
		})
		if err != nil {
			t.Fatal(err)
		}
		validateReport(t, r)
		out := map[string]report.Image{}
		for _, i := range r.Images {
			out[i.ID] = i
		}
		if r.Summary.Reproducibility.Reproduced != 2 {
			t.Errorf("summary: %+v", r.Summary.Reproducibility)
		}
		return out
	}

	rep := &recordingReproducer{}
	img := run(true, rep)
	for name, want := range map[string]struct{ method, digest string }{"tools": {"recipe-rebuild", tools}, "rebased": {"rebase-repeat", rebased}} {
		r := img[name].Reproducibility
		if r.Status != "reproduced" || r.Source != "attestation" || r.Method != want.method || r.Digest != want.digest || r.CheckedAt != "2026-10-05T06:41:09Z" {
			t.Errorf("%s reproducibility: %+v", name, r)
		}
		if b := r.Builder; b == nil || b.ID != "https://github.com/acme/images/actions/runs/123/attempts/1" || b.Job != "reproduce" || b.OS != "linux" || b.FactoryVersion != "v0.2.0" || !strings.HasPrefix(b.BuildKit, "moby/buildkit") {
			t.Errorf("%s builder: %+v", name, r.Builder)
		}
		if r.Signer == nil || r.Signer.Identity != ourSigner || !strings.HasPrefix(r.Ref, host+"/"+name+"@sha256:") || !strings.Contains(r.Detail, "didn't rebuild") {
			t.Errorf("%s attestation: signer %+v ref %q detail %q", name, r.Signer, r.Ref, r.Detail)
		}
		if img[name].Verdict.Status != "verified" {
			t.Errorf("%s verdict: %+v", name, img[name].Verdict)
		}
	}
	// Attested images aren't rebuilt; the rest are, but for strangers, whose
	// recipe didn't verify.
	rebuilt := strings.Join(rep.refs, " ")
	for _, n := range names {
		if was := strings.Contains(rebuilt, host+"/"+n+"@"); was != (n != "tools" && n != "rebased" && n != "strangers") {
			t.Errorf("%s rebuilt: %v (%s)", n, was, rebuilt)
		}
	}
	for name, why := range map[string]string{
		"forged":      "is failed",
		"borrowed":    "isn't a recipe or rebase record verified on this image",
		"otherdigest": "not this image's digest",
		"wrongmethod": "doesn't match what it was made from",
		"strangers":   "isn't a recipe or rebase record verified on this image",
	} {
		r := img[name].Reproducibility
		local := "couldn't finish"
		if name == "strangers" {
			local = "Only verified recipes"
		}
		if r.Status == "reproduced" || r.Source == "attestation" || r.Signer != nil || !strings.Contains(r.Detail, why) || !strings.Contains(r.Detail, local) {
			t.Errorf("%s: %+v, want not counted because it %s", name, r, why)
		}
		if name != "strangers" && img[name].Verdict.Status != "unverified" {
			t.Errorf("%s verdict: %+v", name, img[name].Verdict)
		}
	}

	// Without --reproduce the attestation still says it reproduced; nothing
	// else was checked.
	img = run(false, nil)
	if r := img["tools"].Reproducibility; r.Status != "reproduced" || r.Source != "attestation" {
		t.Errorf("tools without --reproduce: %+v", r)
	}
	if r := img["borrowed"].Reproducibility; r.Status != "not-checked" || r.Source != "" || !strings.Contains(r.Detail, "wasn't counted") {
		t.Errorf("borrowed without --reproduce: %+v", r)
	}
}

// TestBoundReproduction covers each way a verified reproduction attestation
// can fail to be about this image and its verified recipe or rebase record.
func TestBoundReproduction(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("c", 64)
	recipe := strings.Repeat("1", 64)
	from := map[string]string{recipe: PredicateRecipe}
	statement := func(subjects []string, pred map[string]any) []byte {
		var subs []any
		for _, s := range subjects {
			subs = append(subs, map[string]any{"name": "r", "digest": map[string]string{"sha256": strings.TrimPrefix(s, "sha256:")}})
		}
		b, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": PredicateReproduction, "subject": subs, "predicate": pred})
		return b
	}
	good := func() map[string]any {
		return reproductionPredicateFor("recipe-rebuild", "r@"+digest, digest, PredicateRecipe, recipe)
	}
	with := func(k string, v any) map[string]any { p := good(); p[k] = v; return p }
	for _, c := range []struct {
		name      string
		statement []byte
		want      string
	}{
		{"good", statement([]string{digest}, good()), ""},
		{"unreadable", []byte("{"), "can't be read"},
		{"no subject", statement(nil, good()), "names no subject"},
		{"two subjects", statement([]string{digest, other}, good()), "not only this image"},
		{"another image", statement([]string{digest}, with("image", "r@"+other)), "not this image"},
		{"unknown method", statement([]string{digest}, with("method", "rebuilt-by-hand")), "neither recipe-rebuild nor rebase-repeat"},
		{"from another type", statement([]string{digest}, with("from", map[string]any{"predicateType": PredicateRebase, "digest": map[string]string{"sha256": recipe}})), "doesn't match"},
		{"no time", statement([]string{digest}, with("reproducedAt", "yesterday")), "isn't a time"},
	} {
		_, _, err := boundReproduction(verifiedCopy{Found: Found{Statement: c.statement}}, digest, from)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
