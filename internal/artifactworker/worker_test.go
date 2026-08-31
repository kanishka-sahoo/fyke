package artifactworker

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestAnalyzeArchiveIsBoundedAndNeverExtracts(t *testing.T) {
	var body bytes.Buffer
	w := zip.NewWriter(&body)
	for _, name := range []string{"../../escape.txt", "safe/readme.txt"} {
		file, e := w.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = file.Write([]byte("content"))
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	result := Analyze(body.Bytes())
	if result.Archive == nil || result.Archive.Format != "zip" || len(result.Archive.Entries) != 2 {
		t.Fatalf("analysis=%#v", result)
	}
	if strings.Contains(result.Archive.Entries[0], "..") {
		t.Fatalf("unsafe traversal entry: %q", result.Archive.Entries[0])
	}
}
