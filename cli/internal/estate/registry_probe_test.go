package estate

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
)

// requestCounts records what a client actually asked the registry for. Several
// claims in this package are about REQUEST behaviour rather than return values —
// "reading a trend pulls no blobs", "an unchanged file is not re-uploaded" — and
// those are only checkable by watching the wire.
type requestCounts struct {
	mu       sync.Mutex
	blobGET  int
	uploaded map[string]bool
}

var (
	blobFetch  = regexp.MustCompile(`^/v2/.+/blobs/sha256:`)
	blobUpload = regexp.MustCompile(`^/v2/.+/blobs/uploads/`)
)

// observe counts blob traffic by DISTINCT digest, not by request. One blob
// upload is a POST to open a session, PATCH to stream, and PUT to finalize with
// ?digest=..., so counting requests reports one blob three times — which is how
// the first version of this helper produced a false failure.
func (r *requestCounts) observe(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case req.Method == http.MethodGet && blobFetch.MatchString(req.URL.Path):
		r.blobGET++
	case req.Method == http.MethodPut && blobUpload.MatchString(req.URL.Path):
		if digest := req.URL.Query().Get("digest"); digest != "" {
			r.uploaded[digest] = true
		}
	}
}

func (r *requestCounts) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blobGET = 0
	r.uploaded = map[string]bool{}
}

func (r *requestCounts) blobGets() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blobGET
}

func (r *requestCounts) blobUploads() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.uploaded)
}

// countingRegistry is an in-process registry that records blob traffic.
func countingRegistry(t *testing.T) (string, *requestCounts) {
	t.Helper()
	counts := &requestCounts{uploaded: map[string]bool{}}
	inner := registry.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		counts.observe(req)
		inner.ServeHTTP(w, req)
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host, counts
}
