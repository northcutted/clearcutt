package oci

import (
	"archive/tar"
	"io"
	"log"
	"math/rand"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/compare"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestBuildAppPinsIndexBaseAndStampsArtifactLayer(t *testing.T) {
	client, host := testRegistry(t)

	amd64 := v1.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := v1.Platform{OS: "linux", Architecture: "arm64"}
	baseIndex := testIndex(t,
		testBaseImage(t, 101, 2, amd64),
		testBaseImage(t, 202, 2, arm64),
	)
	baseRepo := host + "/bases/java"
	baseRef := baseRepo + ":distroless"
	baseDigest, err := client.PushIndex(baseRef, baseIndex)
	if err != nil {
		t.Fatalf("push base index: %v", err)
	}

	artifact := t.TempDir() + "/app.jar"
	if err := os.WriteFile(artifact, []byte("hello from the app"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	appRef := host + "/apps/payments:1.0.0"
	res, err := client.BuildApp(BuildOptions{
		BaseRef:      baseRef,
		BaseID:       "java21-distroless",
		BaseVersion:  "v1.0.0",
		ArtifactPath: artifact,
		DestPath:     "/workspace/app.jar",
		Entrypoint:   []string{"java", "-jar", "/workspace/app.jar"},
		TargetRef:    appRef,
	})
	if err != nil {
		t.Fatalf("BuildApp: %v", err)
	}
	if want := baseRepo + "@" + baseDigest; res.BaseRef != want {
		t.Fatalf("base ref label pinned the wrong artifact:\nwant %s\ngot  %s", want, res.BaseRef)
	}

	app, err := client.PullImage(appRef)
	if err != nil {
		t.Fatalf("pull app: %v", err)
	}
	cfg, err := app.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if got := cfg.Config.Labels[LabelBaseRef]; got != res.BaseRef {
		t.Errorf("base ref label = %q, want %q", got, res.BaseRef)
	}
	if got := cfg.Config.Labels[LabelBaseLastLayer]; got != res.BaseLastLayer {
		t.Errorf("base boundary label = %q, want %q", got, res.BaseLastLayer)
	}
	if got := cfg.Config.Labels[LabelRebasable]; got != "true" {
		t.Errorf("rebasable label = %q", got)
	}

	layers := imageLayers(t, app)
	appLayer := layers[len(layers)-1]
	appDigest := layerDigest(t, appLayer)
	if appDigest != res.AppLayerDigest {
		t.Fatalf("app layer digest = %s, want %s", appDigest, res.AppLayerDigest)
	}
	if got := readFileFromLayer(t, appLayer, "workspace/app.jar"); string(got) != "hello from the app" {
		t.Fatalf("app layer file content = %q", string(got))
	}
}

func TestRebasePreservesAppLayerAndRuntimeConfig(t *testing.T) {
	client, host := testRegistry(t)
	platform := v1.Platform{OS: "linux", Architecture: "amd64"}

	oldBase := testBaseImage(t, 301, 2, platform)
	newBase := testBaseImage(t, 302, 3, platform)
	oldRepo := host + "/bases/java"
	oldRef := oldRepo + ":v1.0.0"
	oldDigest, err := client.PushImage(oldRef, oldBase)
	if err != nil {
		t.Fatalf("push old base: %v", err)
	}
	newRef := host + "/bases/java:v1.0.1"
	if _, err := client.PushImage(newRef, newBase); err != nil {
		t.Fatalf("push new base: %v", err)
	}

	appLayer := testLayer(t, 303)
	app := testAppImage(t, oldBase, oldRepo+"@"+oldDigest, "java21-distroless", appLayer, platform)
	appRef := host + "/apps/payments:1.0.0"
	if _, err := client.PushImage(appRef, app); err != nil {
		t.Fatalf("push app: %v", err)
	}

	targetRef := host + "/apps/payments:1.0.0-rebased"
	res, err := client.Rebase(RebaseOptions{
		AppRef:         appRef,
		NewBaseRef:     newRef,
		NewBaseID:      "java21-distroless",
		NewBaseVersion: "v1.0.1",
		TargetRef:      targetRef,
	})
	if err != nil {
		t.Fatalf("Rebase: %v", err)
	}
	if res.IsIndex {
		t.Fatal("single image rebase returned an index result")
	}
	if got, want := res.PreservedAppLayers, []string{layerDigest(t, appLayer)}; !stringSlicesEqual(got, want) {
		t.Fatalf("preserved app layers = %v, want %v", got, want)
	}

	rebased, err := client.PullImage(targetRef)
	if err != nil {
		t.Fatalf("pull rebased image: %v", err)
	}
	assertRebasedImage(t, rebased, newBase, []v1.Layer{appLayer})

	cfg, err := rebased.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if got := strings.Join(cfg.Config.Entrypoint, " "); got != "/workspace/app" {
		t.Errorf("entrypoint was not preserved: %q", got)
	}
	if got := cfg.Config.User; got != "65532:65532" {
		t.Errorf("user was not preserved: %q", got)
	}
	if got := cfg.Config.Labels["com.example.owner"]; got != "payments" {
		t.Errorf("custom app label was not preserved: %q", got)
	}
	if got := cfg.Config.Labels[LabelBaseVersion]; got != "v1.0.1" {
		t.Errorf("new base version label = %q", got)
	}
	if got := cfg.Config.Labels[LabelBaseLastLayer]; got != mustLastLayerDigest(t, newBase) {
		t.Errorf("new base boundary label = %q", got)
	}
}

func TestRebaseMultiArchIndexPreservesEachPlatformAppLayer(t *testing.T) {
	client, host := testRegistry(t)
	amd64 := v1.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := v1.Platform{OS: "linux", Architecture: "arm64"}

	oldAmd64 := testBaseImage(t, 401, 2, amd64)
	oldArm64 := testBaseImage(t, 402, 2, arm64)
	newAmd64 := testBaseImage(t, 403, 3, amd64)
	newArm64 := testBaseImage(t, 404, 3, arm64)

	oldIndex := testIndex(t, oldAmd64, oldArm64)
	newIndex := testIndex(t, newAmd64, newArm64)
	oldRepo := host + "/bases/java"
	oldRef := oldRepo + ":v1.0.0"
	if _, err := client.PushIndex(oldRef, oldIndex); err != nil {
		t.Fatalf("push old index: %v", err)
	}
	oldAmd64Digest, err := oldAmd64.Digest()
	if err != nil {
		t.Fatalf("old amd64 digest: %v", err)
	}
	oldArm64Digest, err := oldArm64.Digest()
	if err != nil {
		t.Fatalf("old arm64 digest: %v", err)
	}
	newRef := host + "/bases/java:v1.0.1"
	if _, err := client.PushIndex(newRef, newIndex); err != nil {
		t.Fatalf("push new index: %v", err)
	}

	amdAppLayer := testLayer(t, 405)
	armAppLayer := testLayer(t, 406)
	appIndex := testIndex(t,
		testAppImage(t, oldAmd64, oldRepo+"@"+oldAmd64Digest.String(), "java21-distroless", amdAppLayer, amd64),
		testAppImage(t, oldArm64, oldRepo+"@"+oldArm64Digest.String(), "java21-distroless", armAppLayer, arm64),
	)
	appRef := host + "/apps/payments:1.0.0"
	if _, err := client.PushIndex(appRef, appIndex); err != nil {
		t.Fatalf("push app index: %v", err)
	}

	targetRef := host + "/apps/payments:1.0.0-rebased"
	res, err := client.Rebase(RebaseOptions{
		AppRef:         appRef,
		NewBaseRef:     newRef,
		NewBaseID:      "java21-distroless",
		NewBaseVersion: "v1.0.1",
		TargetRef:      targetRef,
	})
	if err != nil {
		t.Fatalf("Rebase multi-arch: %v", err)
	}
	if !res.IsIndex {
		t.Fatal("multi-arch app rebase did not return an index result")
	}
	if got, want := res.PreservedAppLayers, []string{layerDigest(t, amdAppLayer), layerDigest(t, armAppLayer)}; !stringSlicesEqual(got, want) {
		t.Fatalf("preserved app layers = %v, want %v", got, want)
	}

	pulled, err := client.Pull(targetRef)
	if err != nil {
		t.Fatalf("pull rebased index: %v", err)
	}
	if !pulled.IsIndex {
		t.Fatal("pushed rebased artifact is not an index")
	}
	rebasedAmd64, err := childImage(pulled.Index, &amd64)
	if err != nil {
		t.Fatalf("rebased amd64 child: %v", err)
	}
	rebasedArm64, err := childImage(pulled.Index, &arm64)
	if err != nil {
		t.Fatalf("rebased arm64 child: %v", err)
	}
	assertRebasedImage(t, rebasedAmd64, newAmd64, []v1.Layer{amdAppLayer})
	assertRebasedImage(t, rebasedArm64, newArm64, []v1.Layer{armAppLayer})
}

func TestRebaseRejectsBoundaryMismatch(t *testing.T) {
	client, host := testRegistry(t)
	platform := v1.Platform{OS: "linux", Architecture: "amd64"}

	oldBase := testBaseImage(t, 501, 2, platform)
	newBase := testBaseImage(t, 502, 2, platform)
	oldRepo := host + "/bases/java"
	oldRef := oldRepo + ":v1.0.0"
	oldDigest, err := client.PushImage(oldRef, oldBase)
	if err != nil {
		t.Fatalf("push old base: %v", err)
	}
	newRef := host + "/bases/java:v1.0.1"
	if _, err := client.PushImage(newRef, newBase); err != nil {
		t.Fatalf("push new base: %v", err)
	}

	app := testAppImage(t, oldBase, oldRepo+"@"+oldDigest, "java21-distroless", testLayer(t, 503), platform)
	cfg, err := app.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.Config.Labels[LabelBaseLastLayer] = "sha256:000000"
	app, err = mutate.ConfigFile(app, cfg)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}

	appRef := host + "/apps/payments:1.0.0"
	if _, err := client.PushImage(appRef, app); err != nil {
		t.Fatalf("push app: %v", err)
	}
	_, err = client.Rebase(RebaseOptions{
		AppRef:     appRef,
		NewBaseRef: newRef,
		TargetRef:  host + "/apps/payments:rebased",
	})
	if err == nil || !strings.Contains(err.Error(), "base boundary mismatch") {
		t.Fatalf("expected base boundary mismatch, got %v", err)
	}
}

func testRegistry(t *testing.T) (*Client, string) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return NewInsecureClient(), strings.TrimPrefix(srv.URL, "http://")
}

func testBaseImage(t *testing.T, seed, layers int64, platform v1.Platform) v1.Image {
	t.Helper()
	img, err := random.Image(256, layers, random.WithSource(rand.NewSource(seed)))
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS = platform.OS
	cfg.Architecture = platform.Architecture
	cfg.Config.User = "10001:10001"
	cfg.Config.Entrypoint = []string{"/base-entrypoint"}
	cfg.Config.Labels = map[string]string{
		"org.opencontainers.image.source": "https://github.com/northcutted/clearcutt",
	}
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	return img
}

func testAppImage(t *testing.T, base v1.Image, baseRef, baseID string, appLayer v1.Layer, platform v1.Platform) v1.Image {
	t.Helper()
	app, err := mutate.Append(base, mutate.Addendum{
		Layer: appLayer,
		History: v1.History{
			Author:    "clearcutt-test",
			CreatedBy: "copy app artifact",
			Comment:   "application payload",
		},
	})
	if err != nil {
		t.Fatalf("append app layer: %v", err)
	}
	cfg, err := app.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS = platform.OS
	cfg.Architecture = platform.Architecture
	cfg.Config.User = "65532:65532"
	cfg.Config.WorkingDir = "/workspace"
	cfg.Config.Entrypoint = []string{"/workspace/app"}
	cfg.Config.Env = []string{"APP_ENV=prod"}
	cfg.Config.Labels = map[string]string{
		LabelBaseID:         baseID,
		LabelBaseVersion:    "v1.0.0",
		LabelBaseRef:        baseRef,
		LabelBaseLastLayer:  mustLastLayerDigest(t, base),
		LabelRebasable:      "true",
		"com.example.owner": "payments",
	}
	app, err = mutate.ConfigFile(app, cfg)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	return app
}

func testLayer(t *testing.T, seed int64) v1.Layer {
	t.Helper()
	layer, err := random.Layer(128, types.DockerLayer, random.WithSource(rand.NewSource(seed)))
	if err != nil {
		t.Fatalf("random layer: %v", err)
	}
	return layer
}

func testIndex(t *testing.T, images ...v1.Image) v1.ImageIndex {
	t.Helper()
	adds := make([]mutate.IndexAddendum, 0, len(images))
	for _, img := range images {
		cfg, err := img.ConfigFile()
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		adds = append(adds, mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: cfg.Platform(),
			},
		})
	}
	return mutate.AppendManifests(empty.Index, adds...)
}

func assertRebasedImage(t *testing.T, rebased, newBase v1.Image, appLayers []v1.Layer) {
	t.Helper()
	gotLayers := imageLayers(t, rebased)
	baseLayers := imageLayers(t, newBase)
	if got, want := len(gotLayers), len(baseLayers)+len(appLayers); got != want {
		t.Fatalf("rebased layer count = %d, want %d", got, want)
	}
	for i, want := range baseLayers {
		if err := compare.Layers(gotLayers[i], want); err != nil {
			t.Fatalf("rebased base layer %d differs: %v", i, err)
		}
	}
	for i, want := range appLayers {
		got := gotLayers[len(baseLayers)+i]
		if err := compare.Layers(got, want); err != nil {
			t.Fatalf("rebased app layer %d differs: %v", i, err)
		}
	}
}

func imageLayers(t *testing.T, img v1.Image) []v1.Layer {
	t.Helper()
	layers, err := img.Layers()
	if err != nil {
		t.Fatalf("layers: %v", err)
	}
	return layers
}

func mustLastLayerDigest(t *testing.T, img v1.Image) string {
	t.Helper()
	d, err := lastLayerDigest(img)
	if err != nil {
		t.Fatalf("last layer digest: %v", err)
	}
	return d
}

func layerDigest(t *testing.T, layer v1.Layer) string {
	t.Helper()
	d, err := layer.Digest()
	if err != nil {
		t.Fatalf("layer digest: %v", err)
	}
	return d.String()
}

func readFileFromLayer(t *testing.T, layer v1.Layer, name string) []byte {
	t.Helper()
	rc, err := layer.Uncompressed()
	if err != nil {
		t.Fatalf("uncompressed layer: %v", err)
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read layer tar: %v", err)
		}
		if hdr.Name == name {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			return data
		}
	}
	t.Fatalf("layer did not contain %s", name)
	return nil
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
