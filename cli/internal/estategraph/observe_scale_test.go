package estategraph

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingObserver records how much work each scan actually asked for. The
// scaling claims here are about REQUEST COUNT and wall clock, so they can only
// be checked by watching what the observer is asked to do.
type countingObserver struct {
	mu           sync.Mutex
	digestCalls  int32
	observeCalls int32
	inFlight     int32
	maxInFlight  int32
	latency      time.Duration
	digests      map[string]string
}

func newCountingObserver(latency time.Duration) *countingObserver {
	return &countingObserver{latency: latency, digests: map[string]string{}}
}

func (c *countingObserver) setDigest(ref, digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.digests[ref] = digest
}

func (c *countingObserver) Digest(_ context.Context, ref string) (string, error) {
	atomic.AddInt32(&c.digestCalls, 1)
	c.track()
	c.mu.Lock()
	defer c.mu.Unlock()
	if digest, ok := c.digests[ref]; ok {
		return digest, nil
	}
	return "sha256:unknown", nil
}

func (c *countingObserver) Observe(_ context.Context, ref string) (Observation, error) {
	atomic.AddInt32(&c.observeCalls, 1)
	c.track()
	c.mu.Lock()
	digest := c.digests[ref]
	c.mu.Unlock()
	if digest == "" {
		digest = "sha256:unknown"
	}
	return Observation{
		SourceRef:      ref,
		ManifestDigest: digest,
		Layers:         []LayerObservation{{Digest: "sha256:layer-" + ref, Size: 1024}},
	}, nil
}

// track records concurrency and simulates a network round trip.
func (c *countingObserver) track() {
	now := atomic.AddInt32(&c.inFlight, 1)
	for {
		peak := atomic.LoadInt32(&c.maxInFlight)
		if now <= peak || atomic.CompareAndSwapInt32(&c.maxInFlight, peak, now) {
			break
		}
	}
	time.Sleep(c.latency)
	atomic.AddInt32(&c.inFlight, -1)
}

func inventoryOf(n int) ImagesFile {
	inv := ImagesFile{}
	for i := 0; i < n; i++ {
		inv.Images = append(inv.Images, ImageSpec{
			ID:    fmt.Sprintf("img-%03d", i),
			Image: fmt.Sprintf("reg.test/team/app-%03d:v1", i),
		})
	}
	return inv
}

// TestObservationRunsConcurrently is the first scaling fix. Observation is
// network-bound, so a serial loop spends nearly all its time waiting. This
// asserts the work actually overlaps rather than merely being written to.
func TestObservationRunsConcurrently(t *testing.T) {
	observer := newCountingObserver(20 * time.Millisecond)
	inventory := inventoryOf(32)

	start := time.Now()
	_, stats, err := ObserveImages(context.Background(), inventory, observer, ObserveOptions{
		GeneratedAt: "2026-09-01T00:00:00Z", Concurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if stats.Observed != 32 {
		t.Fatalf("expected 32 observations, got %+v", stats)
	}
	if peak := atomic.LoadInt32(&observer.maxInFlight); peak < 2 {
		t.Fatalf("observations did not overlap; peak in-flight was %d", peak)
	}
	if peak := atomic.LoadInt32(&observer.maxInFlight); peak > 8 {
		t.Errorf("concurrency limit of 8 exceeded; peak in-flight was %d", peak)
	}
	// Serial would be 32 x 20ms = 640ms. Allow generous slack; the point is
	// that it is nothing like serial.
	if elapsed > 400*time.Millisecond {
		t.Errorf("32 images at 20ms each took %v; concurrency is not taking effect", elapsed)
	}
}

// TestObservationIsDeterministicUnderConcurrency guards the property that makes
// snapshot digests meaningful. If completion order leaked into output order,
// two scans of an unchanged estate would produce different bytes, different
// digests, and a history full of changes that never happened.
func TestObservationIsDeterministicUnderConcurrency(t *testing.T) {
	inventory := inventoryOf(40)
	var first string
	for run := 0; run < 8; run++ {
		observations, _, err := ObserveImages(context.Background(), inventory,
			newCountingObserver(time.Millisecond), ObserveOptions{GeneratedAt: "2026-09-01T00:00:00Z", Concurrency: 8})
		if err != nil {
			t.Fatal(err)
		}
		var order string
		for _, obs := range observations.Images {
			order += obs.SourceRef + "\n"
		}
		if run == 0 {
			first = order
			continue
		}
		if order != first {
			t.Fatalf("run %d produced a different observation order; concurrent scans must be byte-identical", run)
		}
	}
}

// TestIncrementalObservationSkipsUnchangedImages is the second scaling fix, and
// the one that matters on a large estate: a daily scan should re-read what
// moved, not everything.
func TestIncrementalObservationSkipsUnchangedImages(t *testing.T) {
	inventory := inventoryOf(100)
	observer := newCountingObserver(0)
	for i := 0; i < 100; i++ {
		observer.setDigest(fmt.Sprintf("reg.test/team/app-%03d:v1", i), fmt.Sprintf("sha256:v1-%03d", i))
	}

	// Day one: nothing to reuse.
	previous, stats, err := ObserveImages(context.Background(), inventory, observer, ObserveOptions{GeneratedAt: "2026-09-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Observed != 100 || stats.Reused != 0 {
		t.Fatalf("first scan should read everything, got %+v", stats)
	}

	// Day two: five images moved.
	for i := 0; i < 5; i++ {
		observer.setDigest(fmt.Sprintf("reg.test/team/app-%03d:v1", i), fmt.Sprintf("sha256:v2-%03d", i))
	}
	atomic.StoreInt32(&observer.observeCalls, 0)
	atomic.StoreInt32(&observer.digestCalls, 0)

	_, stats, err = ObserveImages(context.Background(), inventory, observer, ObserveOptions{
		GeneratedAt: "2026-09-02T00:00:00Z", Previous: &previous,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Reused != 95 || stats.Observed != 5 {
		t.Fatalf("expected 95 reused and 5 re-read, got %+v", stats)
	}
	if got := atomic.LoadInt32(&observer.observeCalls); got != 5 {
		t.Errorf("only the 5 changed images should be fully observed, got %d full reads", got)
	}
	if got := atomic.LoadInt32(&observer.digestCalls); got != 100 {
		t.Errorf("every image needs one cheap digest check, got %d", got)
	}
}

// TestIncrementalObservationReReadsOnDigestFailure: a digest check that errors
// must fall through to a full read, never carry stale data forward silently.
func TestIncrementalObservationReReadsOnDigestFailure(t *testing.T) {
	inventory := inventoryOf(3)
	observer := newCountingObserver(0)
	previous := Observations{Images: []Observation{
		{SourceRef: "reg.test/team/app-000:v1", ManifestDigest: "sha256:stale"},
	}}
	_, stats, err := ObserveImages(context.Background(), inventory, &failingDigestObserver{countingObserver: observer}, ObserveOptions{
		GeneratedAt: "2026-09-01T00:00:00Z", Previous: &previous,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Reused != 0 {
		t.Errorf("a failed digest check must not reuse a stored observation, got %+v", stats)
	}
}

type failingDigestObserver struct{ *countingObserver }

func (failingDigestObserver) Digest(context.Context, string) (string, error) {
	return "", fmt.Errorf("registry unavailable")
}
