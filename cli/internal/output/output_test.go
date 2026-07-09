package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestStructuredAndTableOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintJSON(&buf, map[string]string{"status": "ok"}); err != nil || !strings.Contains(buf.String(), `"status": "ok"`) {
		t.Fatalf("JSON output: err=%v body=%s", err, buf.String())
	}
	buf.Reset()
	if err := PrintYAML(&buf, map[string]string{"status": "ok"}); err != nil || !strings.Contains(buf.String(), "status: ok") {
		t.Fatalf("YAML output: err=%v body=%s", err, buf.String())
	}
	buf.Reset()
	table := NewTablePrinter("NAME", "STATUS")
	table.AddRow("sample", "ok")
	if err := table.Print(&buf); err != nil || !strings.Contains(buf.String(), "sample") {
		t.Fatalf("table output: err=%v body=%s", err, buf.String())
	}
	if err := PrintJSON(&buf, make(chan int)); err == nil {
		t.Fatal("unsupported JSON value should fail")
	}
	if err := PrintYAML(&buf, make(chan int)); err == nil {
		t.Fatal("unsupported YAML value should fail")
	}
	if err := PrintYAML(failingWriter{}, map[string]string{"status": "ok"}); err == nil {
		t.Fatal("YAML writer error should propagate")
	}
}
