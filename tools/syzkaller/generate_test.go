package main

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

var reclaimCompleteChain = []string{
	"syz_open_nfs_lane_profile$client0_knfsd_v41",
	"syz_socket_connect_nfs_lane$client0_knfsd_v41",
	"write$nfs41_exchange_id",
	"recvfrom$nfs41_exchange_id",
	"write$nfs41_create_session",
	"recvfrom$nfs41_create_session",
	"write$nfs41_reclaim_complete",
	"recvfrom$nfs41_reclaim_complete",
}

var bindConnChain = []string{
	"syz_open_nfs_lane_profile$client0_knfsd_v41",
	"syz_socket_connect_nfs_lane$client0_knfsd_v41",
	"write$nfs41_exchange_id",
	"recvfrom$nfs41_exchange_id",
	"write$nfs41_create_session",
	"recvfrom$nfs41_create_session",
	"write$nfs41_bind_conn_to_session",
	"recvfrom$inet_nfs_fuzz_tcp",
}

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

func TestGenerateNFSv41SessionProtocolChain(t *testing.T) {
	target := targetForTest(t)
	req := generateRequest{
		Schema: "syz-generate-request.v1", Seed: 53,
		Enabled: append(append([]string{}, reclaimCompleteChain...),
			"recvfrom$inet_nfs_fuzz_tcp", "setsockopt$sock_linger", "close"),
		Entry:   []string{"write$nfs41_reclaim_complete"},
		Minimal: 1, Generated: 8, MaxCalls: 8,
	}
	out, err := generatePrograms(target, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Minimal) != 1 || len(out.Generated) != 8 {
		t.Fatalf("got %d minimal and %d generated", len(out.Minimal), len(out.Generated))
	}
	for _, generated := range append(append([]generatedProgram{}, out.Minimal...), out.Generated...) {
		p, err := target.Deserialize([]byte(generated.Text), prog.Strict)
		if err != nil {
			t.Fatalf("strict parse: %v\n%s", err, generated.Text)
		}
		chain := make([]*prog.Syscall, 0, len(reclaimCompleteChain))
		for _, name := range reclaimCompleteChain {
			chain = append(chain, target.SyscallMap[name])
		}
		if !validProtocolChain(p, chain) {
			t.Fatalf("program lost the live session chain:\n%s", generated.Text)
		}
		if !validProtocolSemantics(p) {
			t.Fatalf("program lost the live session semantics:\n%s", generated.Text)
		}
		parsed, err := parseProgram(target, []byte(generated.Text))
		if err != nil {
			t.Fatalf("bridge parse: %v\n%s", err, generated.Text)
		}
		if len(parsed.Calls) < len(reclaimCompleteChain) {
			t.Fatalf("short parsed program: %+v", parsed.Calls)
		}
		entry := parsedCall{}
		for _, call := range parsed.Calls {
			if call.Call == "write$nfs41_reclaim_complete" {
				entry = call
			}
		}
		if entry.Call == "" || len(entry.Facts.Origins) != 1 ||
			entry.Facts.Origins[0].Origin != "nfs-profile:knfsd-v41:client0" {
			t.Fatalf("entry call lost lane origin: %+v", entry)
		}
	}
}

func TestGenerateNFSv41BindConnProtocolChain(t *testing.T) {
	target := targetForTest(t)
	req := generateRequest{
		Schema: "syz-generate-request.v1", Seed: 53,
		Enabled: bindConnChain, Entry: []string{"write$nfs41_bind_conn_to_session"},
		Minimal: 1, Generated: 0, MaxCalls: 8,
	}
	out, err := generatePrograms(target, req)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(out.Minimal[0].Text), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	chain := make([]*prog.Syscall, 0, len(bindConnChain))
	for _, name := range bindConnChain {
		chain = append(chain, target.SyscallMap[name])
	}
	if !validProtocolChain(p, chain) || !validProtocolSemantics(p) {
		t.Fatalf("generated invalid live BIND chain:\n%s", out.Minimal[0].Text)
	}
	if _, err := parseProgram(target, []byte(out.Minimal[0].Text)); err != nil {
		t.Fatalf("bridge parse: %v\n%s", err, out.Minimal[0].Text)
	}
	withoutReply := p.Clone()
	withoutReply.RemoveCall(len(withoutReply.Calls) - 1)
	if _, err := parseProgram(target, withoutReply.SerializeVerbose()); err == nil {
		t.Fatal("accepted BIND_CONN_TO_SESSION without its response barrier")
	}
}

func TestNFSv41SessionProtocolSemanticRefusals(t *testing.T) {
	target := targetForTest(t)
	req := generateRequest{
		Schema: "syz-generate-request.v1", Seed: 53,
		Enabled: reclaimCompleteChain, Entry: []string{"write$nfs41_reclaim_complete"},
		Minimal: 1, Generated: 0, MaxCalls: 8,
	}
	out, err := generatePrograms(target, req)
	if err != nil {
		t.Fatal(err)
	}
	base, err := target.Deserialize([]byte(out.Minimal[0].Text), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*prog.Prog){
		"credential uid": func(p *prog.Prog) {
			for _, call := range p.Calls {
				if call.Meta.Name != "write$nfs41_create_session" {
					continue
				}
				record, _ := structuredRequest(call)
				data, _ := nestedField(record, "msg", "cred", "data")
				value, _ := fieldArg(data, "uid")
				value.(*prog.ConstArg).Val = 1
			}
		},
		"exchange flags": func(p *prog.Prog) {
			for _, call := range p.Calls {
				if call.Meta.Name != "write$nfs41_exchange_id" {
					continue
				}
				args, _ := nestedField(call.Args[1], "msg", "op", "args")
				value, _ := fieldArg(args, "flags")
				value.(*prog.ConstArg).Val = 8
			}
		},
		"create flags": func(p *prog.Prog) {
			for _, call := range p.Calls {
				if call.Meta.Name != "write$nfs41_create_session" {
					continue
				}
				args, _ := nestedField(call.Args[1], "msg", "op", "args")
				value, _ := fieldArg(args, "flags")
				value.(*prog.ConstArg).Val = 1
			}
		},
		"small channel": func(p *prog.Prog) {
			for _, call := range p.Calls {
				if call.Meta.Name != "write$nfs41_create_session" {
					continue
				}
				args, _ := nestedField(call.Args[1], "msg", "op", "args")
				fore, _ := fieldArg(args, "fore")
				value, _ := fieldArg(fore, "maxreqsize")
				value.(*prog.ConstArg).Val = 1
			}
		},
		"per-filesystem reclaim": func(p *prog.Prog) {
			for _, call := range p.Calls {
				if call.Meta.Name != "write$nfs41_reclaim_complete" {
					continue
				}
				args, _ := nestedField(call.Args[1], "msg", "op2", "args")
				value, _ := fieldArg(args, "one_fs")
				value.(*prog.ConstArg).Val = 1
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := base.Clone()
			mutate(p)
			if validProtocolSemantics(p) {
				t.Fatal("accepted invalid session bootstrap semantics")
			}
		})
	}
	any := "write$nfs41_exchange_id(0xffffffffffffffff, " +
		"&(0x7f0000000000)=ANY=[@ANYBLOB=\"00\"], 0x1)\n"
	if _, err := parseProgram(target, []byte(any)); err == nil {
		t.Fatal("accepted a squashed bootstrap request")
	}
	broken := base.Clone()
	broken.RemoveCall(0)
	if _, err := parseProgram(target, broken.SerializeVerbose()); err == nil {
		t.Fatal("accepted a session entry without its complete bootstrap chain")
	}
	withoutReply := base.Clone()
	withoutReply.RemoveCall(len(withoutReply.Calls) - 1)
	if _, err := parseProgram(target, withoutReply.SerializeVerbose()); err == nil {
		t.Fatal("accepted RECLAIM_COMPLETE without its response barrier")
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
