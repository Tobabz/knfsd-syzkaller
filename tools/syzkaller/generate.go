package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"sort"

	"github.com/google/syzkaller/prog"
)

// Programs for a promotion probe campaign (#100, 07 section 5.3). The
// Controller fixes the probes; these are the programs that try to reach
// them, none of them a candidate's:
//
//   - minimal: per entry call, a short program with its constructors and any
//     required request/reply barrier around it;
//   - generated: distinct programs, each generated from a minimal one and
//     mutated over the selection's enabled calls, that still call an entry
//     point. A program that lost every entry call is dropped and counted.
//
// The seed fixes the output for one bridge build. Failures are untyped
// errors whose message starts with a reason (entry_call_not_generatable,
// generated_programs_short, ...).

const maxGenerateCalls = 4096
const maxGenerated = 1024
const maxGenerateAttempts = 64

type generateRequest struct {
	Schema    string   `json:"schema_version"`
	Seed      int64    `json:"seed"`
	Enabled   []string `json:"enabled_calls"`
	Entry     []string `json:"entry_calls"`
	Minimal   int      `json:"minimal_per_entry"`
	Generated int      `json:"generated"`
	MaxCalls  int      `json:"max_calls"`
}

type generatedProgram struct {
	Entry  string `json:"entry_call,omitempty"`
	Text   string `json:"text"`
	Sha256 string `json:"sha256"`
}

type generatedPrograms struct {
	Schema    string             `json:"schema_version"`
	Commit    string             `json:"syzkaller_commit"`
	Target    string             `json:"target"`
	Seed      int64              `json:"seed"`
	Minimal   []generatedProgram `json:"minimal"`
	Generated []generatedProgram `json:"generated"`
	// Mutations that lost every entry call; never in Generated.
	WithoutEntry int `json:"dropped_without_entry_call"`
}

func decodeGenerate(data []byte) (generateRequest, error) {
	var req generateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return req, errors.New("bad generate request")
	}
	if req.Schema != "syz-generate-request.v1" {
		return req, errors.New("unsupported generate request schema")
	}
	if len(req.Enabled) == 0 || len(req.Enabled) > maxGenerateCalls ||
		len(req.Entry) == 0 || len(req.Entry) > maxShapeCalls {
		return req, errors.New("generate request call count out of range")
	}
	if req.Minimal < 1 || req.Minimal > 16 || req.Generated < 0 ||
		req.Generated > maxGenerated || req.MaxCalls < 1 || req.MaxCalls > 64 {
		return req, errors.New("generate request bounds out of range")
	}
	return req, nil
}

func programText(p *prog.Prog) generatedProgram {
	// Strict parsing requires explicit fields for some output structs.
	text := p.SerializeVerbose()
	sum := sha256.Sum256(text)
	return generatedProgram{Text: string(text), Sha256: hex.EncodeToString(sum[:])}
}

type protocolChainSpec struct {
	names      []string
	entryIndex int
}

var protocolChains = map[string]protocolChainSpec{
	"write$nfs41_bind_conn_to_session": {
		names: []string{
			"syz_open_nfs_lane_profile$client0_knfsd_v41",
			"syz_socket_connect_nfs_lane$client0_knfsd_v41",
			"write$nfs41_exchange_id",
			"recvfrom$nfs41_exchange_id",
			"write$nfs41_create_session",
			"recvfrom$nfs41_create_session",
			"write$nfs41_bind_conn_to_session",
			"recvfrom$inet_nfs_fuzz_tcp",
		},
		entryIndex: 6,
	},
	"write$nfs41_reclaim_complete": {
		names: []string{
			"syz_open_nfs_lane_profile$client0_knfsd_v41",
			"syz_socket_connect_nfs_lane$client0_knfsd_v41",
			"write$nfs41_exchange_id",
			"recvfrom$nfs41_exchange_id",
			"write$nfs41_create_session",
			"recvfrom$nfs41_create_session",
			"write$nfs41_reclaim_complete",
			"recvfrom$nfs41_reclaim_complete",
		},
		entryIndex: 6,
	},
}

func resolveProtocolChain(target *prog.Target, meta *prog.Syscall,
	usable map[*prog.Syscall]bool) ([]*prog.Syscall, error) {
	spec, ok := protocolChains[meta.Name]
	if !ok {
		return nil, nil
	}
	chain := make([]*prog.Syscall, 0, len(spec.names))
	for _, name := range spec.names {
		call := target.SyscallMap[name]
		if call == nil || call.Attrs.Disabled || !usable[call] {
			return nil, errors.New("protocol_prerequisite_not_generatable: " + name)
		}
		chain = append(chain, call)
	}
	return chain, nil
}

func resourceName(arg *prog.ResultArg) string {
	if typ, ok := arg.Type().(*prog.ResourceType); ok {
		return typ.Desc.Name
	}
	return ""
}

func nestedField(arg prog.Arg, names ...string) (prog.Arg, bool) {
	var ok bool
	for _, name := range names {
		arg, ok = fieldArg(arg, name)
		if !ok {
			return nil, false
		}
	}
	return arg, true
}

func fixedFields(arg prog.Arg, fields map[string]uint64) bool {
	for name, want := range fields {
		got, ok := fieldValue(arg, name)
		if !ok || got != want {
			return false
		}
	}
	return true
}

func structuredRequest(call *prog.Call) (prog.Arg, bool) {
	if len(call.Args) < 2 || !call.Meta.Attrs.NoSquash {
		return nil, false
	}
	ptr, ok := call.Args[1].(*prog.PointerArg)
	want, typed := call.Meta.Args[1].Type.(*prog.PtrType)
	if !ok || !typed || ptr.Res == nil || ptr.Res.Type() != want.Elem {
		return nil, false
	}
	if _, squashed := ptr.Res.(*prog.DataArg); squashed {
		return nil, false
	}
	return ptr.Res, true
}

func validStableAuthSys(record prog.Arg) bool {
	cred, ok := nestedField(record, "msg", "cred")
	if !ok || cred.Type().Name() != "rpc_auth_sys_stable" ||
		!fixedFields(cred, map[string]uint64{"flavor": 1}) {
		return false
	}
	data, ok := fieldArg(cred, "data")
	if !ok || data.Type().Name() != "rpc_auth_sys_stable_data" ||
		!fixedFields(data, map[string]uint64{
			"stamp": 0, "uid": 0, "gid": 0, "gids_len": 0,
		}) {
		return false
	}
	machine, ok := fieldArg(data, "machinename")
	return ok && machine.Type().Name() == "rpc_auth_sys_stable_machine_name" &&
		fixedFields(machine, map[string]uint64{"length": 0})
}

// validProtocolSemantics keeps the session bootstrap executable while later
// calls are mutated. These are server preconditions, not fuzzing dimensions.
func validProtocolSemantics(p *prog.Prog) bool {
	channel := map[string]uint64{
		"headerpad": 0, "maxreqsize": 0x1000, "maxrespsize": 0x1000,
		"maxresp_cached": 0, "maxops": 8, "maxreqs": 4, "rdma_ird_len": 0,
	}
	for _, call := range p.Calls {
		switch call.Meta.Name {
		case "write$nfs41_exchange_id":
			record, ok := structuredRequest(call)
			if !ok || !validStableAuthSys(record) {
				return false
			}
			args, ok := nestedField(record, "msg", "op", "args")
			if !ok || !fixedFields(args, map[string]uint64{"flags": 0}) {
				return false
			}
		case "write$nfs41_create_session":
			record, ok := structuredRequest(call)
			if !ok || !validStableAuthSys(record) {
				return false
			}
			args, ok := nestedField(record, "msg", "op", "args")
			if !ok || !fixedFields(args, map[string]uint64{"flags": 0}) {
				return false
			}
			for _, name := range []string{"fore", "back"} {
				attrs, ok := fieldArg(args, name)
				if !ok || attrs.Type().Name() != "nfs41_session_channel_attrs" ||
					!fixedFields(attrs, channel) {
					return false
				}
			}
		case "write$nfs41_bind_conn_to_session":
			request, ok := structuredRequest(call)
			records, array := request.(*prog.GroupArg)
			if !ok || !array || len(records.Inner) == 0 {
				return false
			}
			for _, record := range records.Inner {
				if !validStableAuthSys(record) {
					return false
				}
				args, ok := nestedField(record, "msg", "op", "args")
				if !ok || !fixedFields(args, map[string]uint64{"rdma_mode": 0}) {
					return false
				}
			}
		case "write$nfs41_reclaim_complete":
			record, ok := structuredRequest(call)
			if !ok || !validStableAuthSys(record) {
				return false
			}
			args, ok := nestedField(record, "msg", "op2", "args")
			if !ok || !fixedFields(args, map[string]uint64{"one_fs": 0}) {
				return false
			}
		}
	}
	return true
}

func protocolChain(target *prog.Target, names []string) ([]*prog.Syscall, bool) {
	chain := make([]*prog.Syscall, 0, len(names))
	for _, name := range names {
		meta := target.SyscallMap[name]
		if meta == nil {
			return nil, false
		}
		chain = append(chain, meta)
	}
	return chain, true
}

// validRequiredProtocolChains requires every stateful entry call to be at its
// fixed position in the complete request/reply chain. This is also applied to
// parsed input, so a hand-written or mutated program cannot bypass the response
// barrier that keeps remote coverage active through server-side processing.
func validRequiredProtocolChains(p *prog.Prog) bool {
	for at, call := range p.Calls {
		spec, ok := protocolChains[call.Meta.Name]
		if !ok {
			continue
		}
		chain, ok := protocolChain(p.Target, spec.names)
		if !ok || !validProtocolChainAt(p, chain, at-spec.entryIndex) {
			return false
		}
	}
	return true
}

// validProtocolChain proves that the generated request/reply sequence is
// contiguous and that every state-bearing input references the matching
// earlier reply on the same lane socket.
func validProtocolChain(p *prog.Prog, chain []*prog.Syscall) bool {
	for start := 0; start+len(chain) <= len(p.Calls); start++ {
		if validProtocolChainAt(p, chain, start) {
			return true
		}
	}
	return false
}

func validProtocolChainAt(p *prog.Prog, chain []*prog.Syscall, start int) bool {
	if start < 0 || start+len(chain) > len(p.Calls) {
		return false
	}
	for i, meta := range chain {
		if p.Calls[start+i].Meta != meta {
			return false
		}
	}
	open, socket := p.Calls[start].Ret, p.Calls[start+1].Ret
	if open == nil || socket == nil {
		return false
	}
	want := map[string]*prog.Call{
		"nfs41_clientid":     p.Calls[start+3],
		"nfs41_sequenceid":   p.Calls[start+3],
		"nfs41_sessionid_hi": p.Calls[start+5],
		"nfs41_sessionid_lo": p.Calls[start+5],
	}
	producer := map[*prog.ResultArg]*prog.Call{}
	for _, call := range p.Calls[start : start+len(chain)] {
		if call.Ret != nil {
			producer[call.Ret] = call
		}
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			if res, ok := arg.(*prog.ResultArg); ok && res.Dir() != prog.DirIn {
				producer[res] = call
			}
		})
	}
	valid := true
	for i, call := range p.Calls[start : start+len(chain)] {
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			res, ok := arg.(*prog.ResultArg)
			if !ok || res.Dir() == prog.DirOut {
				return
			}
			name := resourceName(res)
			switch {
			case i == 1 && name == "fd_nfs_dir":
				valid = valid && res.Res == open
			case i >= 2 && name == "sock_nfs_fuzz_tcp":
				valid = valid && res.Res == socket
			case want[name] != nil:
				valid = valid && res.Res != nil && producer[res.Res] == want[name]
			}
		})
	}
	if valid {
		return true
	}
	return false
}

func generateProtocolProgram(target *prog.Target, chain []*prog.Syscall, seed int64,
	ct *prog.ChoiceTable) *prog.Prog {
	for attempt := 0; attempt < maxGenerateAttempts; attempt++ {
		p := target.GenerateCallSequence(rand.NewSource(seed+int64(attempt)), chain, ct)
		if p != nil && validRequiredProtocolChains(p) && validProtocolSemantics(p) {
			return p
		}
	}
	return nil
}

// minimize cuts p after its first entry call whose input resources all
// come from constructors, then drops each earlier call the entry call
// does not need.  nil when p has no such call.
func minimize(p *prog.Prog, meta *prog.Syscall) *prog.Prog {
	at := -1
	for k, c := range p.Calls {
		if c.Meta == meta && realResources(c) {
			at = k
			break
		}
	}
	if at < 0 {
		return nil
	}
	for len(p.Calls) > at+1 {
		p.RemoveCall(len(p.Calls) - 1)
	}
	for k := len(p.Calls) - 2; k >= 0; k-- {
		q := p.Clone()
		q.RemoveCall(k)
		if realResources(q.Calls[len(q.Calls)-1]) {
			p = q
		}
	}
	return p
}

// realResources is false when an input resource of the call is a special
// value (-1, 0) rather than a constructor's result: the call would fail.
func realResources(call *prog.Call) bool {
	real := true
	prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
		if res, ok := arg.(*prog.ResultArg); ok && res.Dir() != prog.DirOut &&
			res.Res == nil && !res.Type().Optional() {
			real = false
		}
	})
	return real
}

func callsAny(p *prog.Prog, entry map[*prog.Syscall]bool) bool {
	for _, c := range p.Calls {
		if entry[c.Meta] {
			return true
		}
	}
	return false
}

// constructors is meta and, transitively, the usable calls that make the
// resources it takes.
func constructors(meta *prog.Syscall, usable map[*prog.Syscall]bool) map[*prog.Syscall]bool {
	set := map[*prog.Syscall]bool{meta: true}
	todo := []*prog.Syscall{meta}
	for len(todo) > 0 {
		call := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		prog.ForeachCallType(call, func(t prog.Type, ctx *prog.TypeCtx) {
			res, ok := t.(*prog.ResourceType)
			if !ok || ctx.Dir == prog.DirOut {
				return
			}
			for _, ctor := range res.Desc.Ctors {
				if usable[ctor.Call] && !set[ctor.Call] {
					set[ctor.Call] = true
					todo = append(todo, ctor.Call)
				}
			}
		})
	}
	return set
}

func generatePrograms(target *prog.Target, req generateRequest) (generatedPrograms, error) {
	out := generatedPrograms{Schema: "syz-generated-programs.v1", Commit: sourceCommit,
		Target: targetName, Seed: req.Seed, Minimal: []generatedProgram{},
		Generated: []generatedProgram{}}
	lookup := func(name string) (*prog.Syscall, error) {
		if !callName.MatchString(name) {
			return nil, errors.New("call_unresolved: <invalid>")
		}
		meta := target.SyscallMap[name]
		if meta == nil {
			return nil, errors.New("call_unresolved: " + name)
		}
		if meta.Attrs.Disabled {
			return nil, errors.New("call_disabled: " + name)
		}
		return meta, nil
	}
	enabled := map[*prog.Syscall]bool{}
	for _, name := range req.Enabled {
		meta, err := lookup(name)
		if err != nil {
			return out, err
		}
		enabled[meta] = true
	}
	usable, _ := target.TransitivelyEnabledCalls(enabled)
	entry := map[*prog.Syscall]bool{}
	entryChains := map[*prog.Syscall][]*prog.Syscall{}
	var entries []*prog.Syscall
	for _, name := range req.Entry {
		meta, err := lookup(name)
		if err != nil {
			return out, err
		}
		if !usable[meta] {
			// Not enabled, or its resources have no enabled constructor.
			return out, errors.New("entry_call_not_generatable: " + name)
		}
		if !entry[meta] {
			entry[meta] = true
			entries = append(entries, meta)
		}
		chain, err := resolveProtocolChain(target, meta, usable)
		if err != nil {
			return out, err
		}
		entryChains[meta] = chain
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	ct := target.BuildChoiceTable(nil, usable)
	seen := map[string]bool{}
	var minimal []*prog.Prog
	for i, meta := range entries {
		// A choice table of the entry call and the enabled constructors
		// of its resources; minimize keeps what the entry call needs.
		onlyCalls := constructors(meta, usable)
		if len(entryChains[meta]) != 0 {
			onlyCalls = map[*prog.Syscall]bool{}
			for _, call := range entryChains[meta] {
				onlyCalls[call] = true
			}
		}
		only := target.BuildChoiceTable(nil, onlyCalls)
		made := 0
		for attempt := 0; made < req.Minimal && attempt < maxGenerateAttempts*req.Minimal; attempt++ {
			rs := rand.NewSource(req.Seed + int64(i)<<32 + int64(attempt))
			var p *prog.Prog
			if chain := entryChains[meta]; len(chain) != 0 {
				if len(chain) > req.MaxCalls {
					return out, errors.New("protocol_chain_too_long: " + meta.Name)
				}
				p = generateProtocolProgram(target, chain,
					req.Seed+int64(i)<<32+int64(attempt)*maxGenerateAttempts, only)
			} else {
				p = minimize(target.Generate(rs, req.MaxCalls, only), meta)
			}
			if p == nil {
				continue
			}
			text := programText(p)
			if seen[text.Sha256] {
				continue
			}
			seen[text.Sha256] = true
			text.Entry = meta.Name
			out.Minimal = append(out.Minimal, text)
			minimal = append(minimal, p)
			made++
		}
		if made == 0 {
			return out, errors.New("entry_call_not_generatable: " + meta.Name)
		}
	}
	rnd := rand.New(rand.NewSource(req.Seed ^ 0x5eed))
	for attempt := 0; len(out.Generated) < req.Generated &&
		attempt < maxGenerateAttempts*req.Generated; attempt++ {
		p := minimal[rnd.Intn(len(minimal))].Clone()
		for rounds := 1 + rnd.Intn(4); rounds > 0; rounds-- {
			p.Mutate(rand.NewSource(rnd.Int63()), req.MaxCalls, ct, nil, minimal)
		}
		if !callsAny(p, entry) {
			out.WithoutEntry++
			continue
		}
		validEntry := false
		for meta, chain := range entryChains {
			if !entry[meta] {
				continue
			}
			for _, call := range p.Calls {
				if call.Meta == meta && (len(chain) == 0 ||
					(validRequiredProtocolChains(p) && validProtocolSemantics(p))) {
					validEntry = true
				}
			}
		}
		if !validEntry {
			out.WithoutEntry++
			continue
		}
		text := programText(p)
		if seen[text.Sha256] {
			continue
		}
		seen[text.Sha256] = true
		out.Generated = append(out.Generated, text)
	}
	if len(out.Generated) < req.Generated {
		return out, errors.New("generated_programs_short: could not generate enough distinct programs")
	}
	return out, nil
}
