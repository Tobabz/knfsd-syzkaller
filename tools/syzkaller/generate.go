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
//   - minimal: per entry call, a short program that ends in that call,
//     with the calls that make its resources before it;
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
	text := p.Serialize()
	sum := sha256.Sum256(text)
	return generatedProgram{Text: string(text), Sha256: hex.EncodeToString(sum[:])}
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
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	ct := target.BuildChoiceTable(nil, usable)
	seen := map[string]bool{}
	var minimal []*prog.Prog
	for i, meta := range entries {
		// A choice table of the entry call and the enabled constructors
		// of its resources; minimize keeps what the entry call needs.
		only := target.BuildChoiceTable(nil, constructors(meta, usable))
		made := 0
		for attempt := 0; made < req.Minimal && attempt < maxGenerateAttempts*req.Minimal; attempt++ {
			rs := rand.NewSource(req.Seed + int64(i)<<32 + int64(attempt))
			p := minimize(target.Generate(rs, req.MaxCalls, only), meta)
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
