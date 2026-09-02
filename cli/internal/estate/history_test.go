package estate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func snapshotWith(generatedAt string, images, resolved, proven, stale int) Snapshot {
	graph := fmt.Sprintf(`{"summary":{"observedImages":%d,"resolvedConsumers":%d,"unresolvedConsumers":%d,
	  "staleConsumers":%d,"rootImages":2,"edgesByMethod":{"layer-prefix":%d,"oci-base-name":%d}}}`,
		images, resolved, images-resolved, stale, proven, resolved-proven)
	layers := `{"summary":{"distinctLayers":96,"sharedLayers":12,"storedBytes":703594496}}`
	return Snapshot{
		GeneratedAt: generatedAt,
		Files: map[string][]byte{
			"graph.json":        []byte(graph),
			"layers.json":       []byte(layers),
			"observations.json": []byte(`{"images":[]}`),
		},
	}
}

func TestHistoryAccumulatesSnapshotsInTimeOrder(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	historyRef := host + "/acme/estate:history"

	// Pushed out of order on purpose: a backfilled run must land in the right
	// place on the trend line, not at the end of the push log.
	for _, day := range []struct {
		at                              string
		images, resolved, proven, stale int
	}{
		{"2026-09-02T00:00:00Z", 21, 9, 7, 1},
		{"2026-08-31T00:00:00Z", 19, 3, 2, 6},
		{"2026-09-01T00:00:00Z", 20, 6, 4, 3},
	} {
		snapshotRef := fmt.Sprintf("%s/acme/estate:%s", host, day.at[:10])
		if _, _, err := client.PushSnapshot(snapshotRef, historyRef,
			snapshotWith(day.at, day.images, day.resolved, day.proven, day.stale)); err != nil {
			t.Fatalf("push %s: %v", day.at, err)
		}
	}

	history, err := client.ReadHistory(historyRef)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	if len(history.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(history.Entries))
	}
	wantOrder := []string{"2026-08-31T00:00:00Z", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"}
	for i, want := range wantOrder {
		if got := history.Entries[i].GeneratedAt; got != want {
			t.Errorf("entry %d generatedAt = %s, want %s (history must be time-ordered, not push-ordered)", i, got, want)
		}
	}

	first, last, ok := history.Delta()
	if !ok {
		t.Fatal("a 3-entry history should report a delta")
	}
	if first.Metrics.Resolved != 3 || last.Metrics.Resolved != 9 {
		t.Errorf("delta should span 3 -> 9 resolved, got %d -> %d", first.Metrics.Resolved, last.Metrics.Resolved)
	}
	if first.Metrics.Stale != 6 || last.Metrics.Stale != 1 {
		t.Errorf("delta should span 6 -> 1 stale, got %d -> %d", first.Metrics.Stale, last.Metrics.Stale)
	}
}

// TestHistoryReadPullsNoSnapshotBlobs is the property that makes this design
// worth the index: a trend over a long series must not cost a blob pull per
// entry. The metrics live in the index annotations, so reading a year of daily
// snapshots is one manifest fetch.
func TestHistoryReadPullsNoSnapshotBlobs(t *testing.T) {
	host, counts := countingRegistry(t)
	client := NewInsecureClient()
	historyRef := host + "/acme/estate:history"

	const days = 30
	for i := 0; i < days; i++ {
		at := fmt.Sprintf("2026-09-%02dT00:00:00Z", i+1)
		ref := fmt.Sprintf("%s/acme/estate:day-%02d", host, i+1)
		if _, _, err := client.PushSnapshot(ref, historyRef, snapshotWith(at, 19, i, i/2, 19-i)); err != nil {
			t.Fatalf("push day %d: %v", i+1, err)
		}
	}

	counts.reset()
	history, err := client.ReadHistory(historyRef)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Entries) != days {
		t.Fatalf("expected %d entries, got %d", days, len(history.Entries))
	}
	if blobs := counts.blobGets(); blobs != 0 {
		t.Errorf("reading a %d-entry history pulled %d blob(s); the trend must come from index annotations alone", days, blobs)
	}
	// Sanity: the metrics really did survive the round trip through annotations.
	if history.Entries[days-1].Metrics.Resolved != days-1 {
		t.Errorf("last entry resolved = %d, want %d", history.Entries[days-1].Metrics.Resolved, days-1)
	}
}

// TestUnchangedSnapshotDoesNotAddAHistoryEntry: a scheduled job that re-runs
// against an unchanged estate must not fill the series with rows that say
// nothing happened.
func TestUnchangedSnapshotDoesNotAddAHistoryEntry(t *testing.T) {
	host := testRegistry(t)
	client := NewInsecureClient()
	historyRef := host + "/acme/estate:history"
	snapshot := snapshotWith("2026-09-01T00:00:00Z", 19, 3, 2, 6)

	for i := 0; i < 3; i++ {
		if _, _, err := client.PushSnapshot(host+"/acme/estate:latest", historyRef, snapshot); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	history, err := client.ReadHistory(historyRef)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Entries) != 1 {
		t.Fatalf("three pushes of identical content should leave one entry, got %d", len(history.Entries))
	}
}

// TestHistoryStorageIsIncremental is the claim the design rests on: snapshots
// are logically complete but physically deltas, because a blob that did not
// change is stored once and referenced by every snapshot that contains it.
func TestHistoryStorageIsIncremental(t *testing.T) {
	host, counts := countingRegistry(t)
	client := NewInsecureClient()
	historyRef := host + "/acme/estate:history"

	// Day one: everything is new.
	day1 := snapshotWith("2026-09-01T00:00:00Z", 19, 3, 2, 6)
	if _, _, err := client.PushSnapshot(host+"/acme/estate:d1", historyRef, day1); err != nil {
		t.Fatal(err)
	}

	// Day two: the graph moved, but observations.json is byte-identical.
	day2 := snapshotWith("2026-09-02T00:00:00Z", 19, 5, 4, 4)
	day2.Files["observations.json"] = day1.Files["observations.json"]

	counts.reset()
	if _, _, err := client.PushSnapshot(host+"/acme/estate:d2", historyRef, day2); err != nil {
		t.Fatal(err)
	}
	// Day two differs from day one in graph.json alone — observations.json and
	// layers.json are byte-identical — so exactly one blob is new. Everything
	// else is already in the registry under the same digest and is referenced,
	// not re-sent. That is the whole "complete snapshots, delta storage" claim,
	// measured on the wire rather than asserted in a comment.
	if uploaded := counts.blobUploads(); uploaded != 1 {
		t.Errorf("day two changed one file of three, so exactly 1 blob should upload; got %d", uploaded)
	}
}

// TestCommittedHistoryFixtureIsReadable guards the series the site renders.
// history.json is a real export, and the site's Zod schema parses it at build
// time — so a change to the History shape that the site cannot read should fail
// here rather than as a broken page.
func TestCommittedHistoryFixtureIsReadable(t *testing.T) {
	raw, err := os.ReadFile("../../../examples/public-estate/history.json")
	if err != nil {
		t.Skipf("history fixture not present: %v", err)
	}
	var history History
	if err := json.Unmarshal(raw, &history); err != nil {
		t.Fatalf("the committed history fixture must parse as a History: %v", err)
	}
	if len(history.Entries) < 2 {
		t.Fatalf("the fixture should carry at least two snapshots so the site can render a trend, got %d", len(history.Entries))
	}
	for i, entry := range history.Entries {
		if entry.Digest == "" || entry.GeneratedAt == "" {
			t.Errorf("entry %d must name a digest and a timestamp, got %+v", i, entry)
		}
		if entry.Metrics.Images == 0 {
			t.Errorf("entry %d carries no metrics; the trend would render empty rows", i)
		}
	}
	// Entries must be time-ordered, because the site renders them in slice order
	// and reads the first and last as the trend endpoints.
	for i := 1; i < len(history.Entries); i++ {
		if history.Entries[i-1].GeneratedAt > history.Entries[i].GeneratedAt {
			t.Errorf("entries are not time-ordered at index %d: %s then %s",
				i, history.Entries[i-1].GeneratedAt, history.Entries[i].GeneratedAt)
		}
	}
}

// TestSeparateHistoryRepoSuggestion checks the escape hatch offered when a
// registry's immutability policy cannot be scoped to one tag.
func TestSeparateHistoryRepoSuggestion(t *testing.T) {
	for ref, want := range map[string]string{
		"ghcr.io/acme/app:history":        "ghcr.io/acme/app-history:history",
		"registry.io:5000/team/x:history": "registry.io:5000/team/x-history:history",
		"ghcr.io/acme/app":                "ghcr.io/acme/app-history:history",
	} {
		if got := suggestSeparateHistoryRepo(ref); got != want {
			t.Errorf("suggestSeparateHistoryRepo(%q) = %q, want %q", ref, got, want)
		}
	}
}

// TestMetricRatiosAreHonest pins the two derived numbers the estate page leads
// with. Coverage is easy to move; proof share is not, and conflating them would
// let an estate look governed by labelling its own images.
func TestMetricRatiosAreHonest(t *testing.T) {
	m := Metrics{Resolved: 8, Unresolved: 12, Proven: 2}
	if got := m.Coverage(); got < 0.39 || got > 0.41 {
		t.Errorf("coverage of 8 resolved out of 20 should be ~0.40, got %v", got)
	}
	if got := m.ProvenShare(); got != 0.25 {
		t.Errorf("proof share of 2 proven out of 8 resolved should be 0.25, got %v", got)
	}

	// Adding label-derived edges raises coverage but must NOT raise proof share.
	labelled := Metrics{Resolved: 16, Unresolved: 4, Proven: 2}
	if labelled.Coverage() <= m.Coverage() {
		t.Error("resolving more images should raise coverage")
	}
	if labelled.ProvenShare() >= m.ProvenShare() {
		t.Error("resolving more images by label must not raise the proof share")
	}

	// Empty estates report zero rather than dividing by zero.
	empty := Metrics{}
	if empty.Coverage() != 0 || empty.ProvenShare() != 0 {
		t.Errorf("an empty estate should report zero ratios, got %v / %v", empty.Coverage(), empty.ProvenShare())
	}
	if !strings.Contains(m.String(), "resolved=8") {
		t.Errorf("String should summarise the metrics, got %q", m.String())
	}
}

// TestExtractMetricsToleratesPartialSnapshots: a snapshot written before
// `graph layers` ran should still yield the metrics it can supply, rather than
// failing and losing the whole trend point.
func TestExtractMetricsToleratesPartialSnapshots(t *testing.T) {
	graphOnly := Snapshot{Files: map[string][]byte{
		"graph.json": []byte(`{"summary":{"observedImages":19,"resolvedConsumers":3,"edgesByMethod":{"layer-prefix":2}}}`),
	}}
	m := ExtractMetrics(graphOnly)
	if m.Images != 19 || m.Resolved != 3 || m.Proven != 2 {
		t.Fatalf("graph metrics should be read without layers.json, got %+v", m)
	}
	if m.Layers != 0 {
		t.Errorf("layer metrics should stay zero when layers.json is absent, got %d", m.Layers)
	}

	// Malformed JSON must not panic or poison the metrics.
	broken := Snapshot{Files: map[string][]byte{"graph.json": []byte(`{not json`)}}
	if got := ExtractMetrics(broken); got != (Metrics{}) {
		t.Errorf("unreadable graph.json should yield zero metrics, got %+v", got)
	}
}
