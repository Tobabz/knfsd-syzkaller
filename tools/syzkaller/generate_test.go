package main

import (
	"strings"
	"testing"
)

func campaignRequest() generateRequest {
	return generateRequest{
		Schema: "syz-generate-request.v1", Seed: 7,
		Enabled: []string{"syz_open_nfs_lane_profile$client0_knfsd_v41",
			"getdents64", "mkdirat", "close"},
		Entry:   []string{"getdents64"},
		Minimal: 2, Generated: 16, MaxCalls: 8,
	}
}

func TestGenerateCampaignPrograms(t *testing.T) {
	target := targetForTest(t)
	out, err := generatePrograms(target, campaignRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Minimal) != 2 || len(out.Generated) != 16 {
		t.Fatalf("got %d minimal, %d generated", len(out.Minimal), len(out.Generated))
	}
	seen := map[string]bool{}
	for _, p := range append(append([]generatedProgram{}, out.Minimal...), out.Generated...) {
		if seen[p.Sha256] {
			t.Fatalf("duplicate program %s", p.Sha256)
		}
		seen[p.Sha256] = true
		if !strings.Contains(p.Text, "getdents64(") {
			t.Fatalf("program without the entry call:\n%s", p.Text)
		}
		// Every program is one the strict parser takes.
		if _, err := parseProgram(target, []byte(p.Text)); err != nil {
			t.Fatalf("%v:\n%s", err, p.Text)
		}
		for _, line := range strings.Split(strings.TrimSpace(p.Text), "\n") {
			name := strings.SplitN(line, "(", 2)[0]
			if i := strings.Index(name, "= "); i >= 0 {
				name = name[i+2:]
			}
			if !map[string]bool{"syz_open_nfs_lane_profile$client0_knfsd_v41": true,
				"getdents64": true, "mkdirat": true, "close": true}[name] {
				t.Fatalf("call %q is not enabled:\n%s", name, p.Text)
			}
		}
	}
	for _, p := range out.Minimal {
		lines := strings.Split(strings.TrimSpace(p.Text), "\n")
		if p.Entry != "getdents64" || !strings.Contains(lines[len(lines)-1], "getdents64(") {
			t.Fatalf("a minimal program ends in its entry call:\n%s", p.Text)
		}
		// The directory comes from the only enabled constructor.
		if !strings.Contains(p.Text, "syz_open_nfs_lane_profile$client0_knfsd_v41(") {
			t.Fatalf("minimal program without the lane:\n%s", p.Text)
		}
	}
	again, err := generatePrograms(target, campaignRequest())
	if err != nil {
		t.Fatal(err)
	}
	for i := range out.Generated {
		if again.Generated[i].Sha256 != out.Generated[i].Sha256 {
			t.Fatal("one seed gave two campaigns")
		}
	}
}

func TestGenerateRefusesWhatItCannotGenerate(t *testing.T) {
	target := targetForTest(t)
	for reason, change := range map[string]func(*generateRequest){
		"entry_call_not_generatable": func(r *generateRequest) { r.Entry = []string{"read"} },
		"call_unresolved":            func(r *generateRequest) { r.Enabled = append(r.Enabled, "nope") },
		"call_disabled":              func(r *generateRequest) { r.Enabled = append(r.Enabled, "clone3") },
	} {
		req := campaignRequest()
		change(&req)
		_, err := generatePrograms(target, req)
		if err == nil || !strings.HasPrefix(err.Error(), reason+": ") {
			t.Fatalf("%s: got %v", reason, err)
		}
	}
	// getdents64 without an enabled directory constructor.
	req := campaignRequest()
	req.Enabled = []string{"getdents64"}
	if _, err := generatePrograms(target, req); err == nil {
		t.Fatal("generated an entry call without its resources")
	}
	for _, data := range []string{`{}`, `{"schema_version":"syz-generate-request.v1"}`,
		`{"schema_version":"syz-generate-request.v1","enabled_calls":["getdents64"],` +
			`"entry_calls":["getdents64"],"minimal_per_entry":1,"generated":5000,"max_calls":8}`} {
		if _, err := decodeGenerate([]byte(data)); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}
