package queue

import (
	"path/filepath"
	"testing"
	"time"

	"gateway/internal/model"
)

func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fs := &FileStore{Dir: dir}
	e := &Entry{
		ID: "a/b/1", Domain: "d.example", From: "s@c", To: []string{"r@d.example"},
		Body: []byte("x"), Enqueued: time.Unix(1_700_000_000, 0),
		PlannedMode: model.ModeEnforce, PlannedGeneration: 7,
		Attempts: 2, LastErr: "boom", Hold: "waiting", Released: true,
	}
	if err := fs.Put(e); err != nil {
		t.Fatal(err)
	}
	got, err := fs.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries", len(got))
	}
	g := got[0]
	if g.PlannedMode != model.ModeEnforce || g.PlannedGeneration != 7 ||
		g.LastErr != "boom" || !g.Released || g.Attempts != 2 {
		t.Fatalf("round trip lost fields: %+v", g)
	}
	// The slash in the id must not escape the directory.
	if _, err := filepath.Glob(filepath.Join(dir, "..", "*")); err != nil {
		_ = err
	}
	if err := fs.Delete(e.ID); err != nil {
		t.Fatal(err)
	}
	if err := fs.Delete(e.ID); err != nil {
		t.Fatalf("second delete should be a no-op: %v", err)
	}
	got, err = fs.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("entry survived delete: %+v", got)
	}
}

func TestFileStoreIgnoresCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	fs := &FileStore{Dir: dir}
	if err := fs.Put(&Entry{ID: "good", Domain: "d"}); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(dir, "bad.json", "{not json"); err != nil {
		t.Fatal(err)
	}
	got, err := fs.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "good" {
		t.Fatalf("corrupt file derailed the queue: %+v", got)
	}
}

func TestSanctionedRelaxation(t *testing.T) {
	mk := func(reason string) []model.Transition {
		return []model.Transition{{From: model.ModeEnforce, To: model.ModeTesting, Reason: reason}}
	}
	for _, ok := range []string{"authenticated_downgrade", "downgrade_stabilized"} {
		if !sanctionedRelaxation(mk(ok)) {
			t.Errorf("%s not sanctioned", ok)
		}
	}
	for _, bad := range []string{"downgrade_rejected_policy_valid", "downgrade_stabilizing", "policy_refresh_identity", ""} {
		if sanctionedRelaxation(mk(bad)) {
			t.Errorf("%s wrongly sanctioned", bad)
		}
	}
	// An upgrade must not read as a relaxation.
	h := []model.Transition{{From: model.ModeTesting, To: model.ModeEnforce, Reason: "upgrade"}}
	if sanctionedRelaxation(h) {
		t.Error("an upgrade was read as a relaxation")
	}
}
