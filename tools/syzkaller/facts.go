package main

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/google/syzkaller/prog"
)

type originFact struct {
	Index  int    `json:"argument_index"`
	Type   string `json:"resource_type"`
	Origin string `json:"origin"`
}
type integerFact struct {
	Index int    `json:"argument_index"`
	Value uint64 `json:"value"`
}
type byteFact struct {
	Index  int    `json:"argument_index"`
	Length uint64 `json:"length_bytes"`
}
type facts struct {
	Origins  []originFact  `json:"origins"`
	Integers []integerFact `json:"integers"`
	Bytes    []byteFact    `json:"byte_lengths"`
}
type parsedCall struct {
	Index        int    `json:"index"`
	Call         string `json:"call"`
	Availability string `json:"availability"`
	Facts        facts  `json:"resource_facts"`
}
type acquisition struct {
	Profile string `json:"profile"`
	Origin  string `json:"resource_origin"`
}
type usage struct {
	Bytes     int `json:"program_bytes"`
	Calls     int `json:"call_count"`
	Resources int `json:"resource_count"`
}
type programResult struct {
	Digest       string        `json:"program_sha256"`
	Calls        []parsedCall  `json:"calls"`
	Usage        usage         `json:"usage"`
	Acquisitions []acquisition `json:"nfs_acquisitions"`
}

func parseProgram(target *prog.Target, data []byte) (programResult, error) {
	result := programResult{Digest: fmt.Sprintf("%x", sha256.Sum256(data)),
		Calls: []parsedCall{}, Acquisitions: []acquisition{}}
	if len(data) > maxProgramBytes {
		return result, fmt.Errorf("program byte limit exceeded")
	}
	p, err := target.Deserialize(data, prog.Strict)
	if err != nil {
		return result, fmt.Errorf("strict parse: %w", err)
	}
	if len(p.Calls) == 0 || len(p.Calls) > maxCalls {
		return result, fmt.Errorf("call limit exceeded")
	}
	result.Usage = usage{Bytes: len(data), Calls: len(p.Calls)}
	roots := map[*prog.ResultArg]string{}
	acquired := map[acquisition]bool{}
	for index, call := range p.Calls {
		if call.Meta.Attrs.Disabled {
			return result, fmt.Errorf("disabled call")
		}
		if call.Props != (prog.CallProps{}) {
			return result, fmt.Errorf("call properties are unsupported")
		}
		f := facts{Origins: []originFact{}, Integers: []integerFact{}, Bytes: []byteFact{}}
		// Count every typed resource occurrence (including references/returns),
		// pointer and buffer node. This is a conservative syntax budget, not a
		// runtime live-FD estimate and never deduplicates claimed annotations.
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			switch arg.(type) {
			case *prog.ResultArg, *prog.PointerArg, *prog.DataArg:
				result.Usage.Resources++
			}
		})
		if result.Usage.Resources > maxResources {
			return result, fmt.Errorf("resource limit exceeded")
		}
		for i, arg := range call.Args {
			if value, ok := scalar(arg); ok {
				f.Integers = append(f.Integers, integerFact{i, value})
			}
			if ptr, ok := arg.(*prog.PointerArg); ok && ptr.Res != nil {
				if buf, ok := ptr.Res.(*prog.DataArg); ok {
					f.Bytes = append(f.Bytes, byteFact{i, buf.Size()})
				}
			}
			if ref, ok := arg.(*prog.ResultArg); ok && ref.Res != nil && ref.OpDiv == 0 && ref.OpAdd == 0 {
				if origin := roots[ref.Res]; origin != "" && isFD(ref) {
					f.Origins = append(f.Origins, originFact{i, "fd", origin})
				}
			}
		}
		result.Calls = append(result.Calls, parsedCall{index, call.Meta.Name, "available", f})
		if a, ok := profileAcquisition(call); ok {
			roots[call.Ret] = a.Origin
			acquired[a] = true
		} else if isNfsAcquisition(call.Meta.CallName) {
			// Silently omitting an acquisition could hide a second, conflicting
			// profile beside a supported acquisition in the same program.
			return result, fmt.Errorf("NFS acquisition profile is unverified")
		} else if call.Meta.CallName == "close" && len(call.Args) == 1 {
			ref, ok := call.Args[0].(*prog.ResultArg)
			if ok && ref.Res != nil && ref.OpAdd == 0 && ref.OpDiv == 0 {
				delete(roots, ref.Res)
			} else {
				clear(roots)
			}
		} else if !preservesRoots(call.Meta.CallName) {
			// Unknown calls may close/rebind descriptors. No inferred dup,
			// openat, socket, path, or nested-memory resource provenance.
			clear(roots)
		}
	}
	for a := range acquired {
		result.Acquisitions = append(result.Acquisitions, a)
	}
	sort.Slice(result.Acquisitions, func(i, j int) bool {
		a, b := result.Acquisitions[i], result.Acquisitions[j]
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		return a.Origin < b.Origin
	})
	return result, nil
}

func isNfsAcquisition(name string) bool {
	switch name {
	case "syz_open_nfs_lane_profile", "syz_open_nfs_lane", "syz_open_nfs_lane_pair",
		"syz_socket_connect_nfs", "syz_socket_connect_nfs_pair", "syz_socket_connect_nfs_plain":
		return true
	}
	return false
}

func isFD(arg *prog.ResultArg) bool {
	t, ok := arg.Type().(*prog.ResourceType)
	return ok && len(t.Desc.Kind) > 0 && t.Desc.Kind[0] == "fd"
}

func scalar(arg prog.Arg) (uint64, bool) {
	a, ok := arg.(*prog.ConstArg)
	if !ok || a.Dir() != prog.DirIn {
		return 0, false
	}
	switch a.Type().(type) {
	case *prog.ConstType, *prog.IntType, *prog.FlagsType, *prog.LenType:
	default:
		return 0, false // checksums and per-process values are dynamic
	}
	t := a.Type()
	bits := t.Size() * 8
	// Syzlang does not carry signedness. Only values representable identically
	// by signed and unsigned operands are justified as mathematical integers.
	if t.Format() != prog.FormatNative || t.BitfieldLength() != 0 || bits == 0 || bits > 64 || a.Val >= uint64(1)<<(bits-1) {
		return 0, false
	}
	return a.Val, true
}

func profileAcquisition(call *prog.Call) (acquisition, bool) {
	profiles := []struct{ name, suffix string }{
		{"knfsd-v3", "knfsd_v3"}, {"knfsd-v40", "knfsd_v40"},
		{"knfsd-v41", "knfsd_v41"}, {"knfsd-v42", "knfsd_v42"},
		{"ganesha-v41", "ganesha_v41"},
	}
	if call.Meta.CallName != "syz_open_nfs_lane_profile" || len(call.Args) != 2 || call.Ret == nil || call.Ret.Type().Name() != "fd_nfs_dir" {
		return acquisition{}, false
	}
	for p, profile := range profiles {
		for client := 0; client < 2; client++ {
			name := fmt.Sprintf("syz_open_nfs_lane_profile$client%d_%s", client, profile.suffix)
			if call.Meta.Name != name {
				continue
			}
			for i, want := range []uint64{uint64(p), uint64(client)} {
				a, ok := call.Args[i].(*prog.ConstArg)
				if !ok {
					return acquisition{}, false
				}
				t, ok := a.Type().(*prog.ConstType)
				if !ok || t.Val != want || a.Val != want {
					return acquisition{}, false
				}
			}
			return acquisition{profile.name, fmt.Sprintf("nfs-profile:%s:client%d", profile.name, client)}, true
		}
	}
	return acquisition{}, false
}

func preservesRoots(name string) bool {
	switch name {
	case "read", "write", "pread64", "pwrite64", "readv", "writev", "preadv2", "pwritev2",
		"getdents", "getdents64", "fsync", "fdatasync", "fstat", "fstatfs", "lseek",
		"ftruncate", "fallocate", "flock", "fchmod", "fchown", "fadvise64", "readahead",
		"sync_file_range", "copy_file_range", "fsetxattr", "fgetxattr", "flistxattr", "fremovexattr",
		"openat", "nanosleep":
		return true
	}
	return false
}
