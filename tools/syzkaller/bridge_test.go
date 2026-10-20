package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

const lane = "r0 = syz_open_nfs_lane_profile$client0_knfsd_v41(0x2, 0x0)\n"

func targetForTest(t *testing.T) *prog.Target {
	t.Helper()
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func mustParse(t *testing.T, source string) programResult {
	t.Helper()
	result, err := parseProgram(targetForTest(t), []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestGeneratedExport(t *testing.T) {
	target := targetForTest(t)
	table := exportTable(target)
	if len(table.Calls) != len(target.Syscalls) || len(table.Calls) < 1000 {
		t.Fatal("incomplete generated table")
	}
	for i, name := range table.Calls {
		if target.SyscallMap[name] == nil || (i > 0 && name <= table.Calls[i-1]) {
			t.Fatalf("bad table: %s", name)
		}
	}
	if target.SyscallMap["syz_open_nfs_lane_profile$client0_knfsd_v41"] == nil {
		t.Fatal("patch series missing")
	}
	if !target.SyscallMap["clone3"].Attrs.Disabled {
		t.Fatal("disabled-call fixture no longer disabled")
	}
}

func TestStrictRefusals(t *testing.T) {
	for _, source := range []string{
		"", "# claimed acquisition: knfsd-v41\n", "unknown_call()\n", "getpid(1)\n",
		"write()\n", "fsync(r99)\n", "clone3(0x0, 0x0)\n", "getpid() trailing\n",
		"getpid() (async)\n", "getpid() (rerun: 1)\n", "getpid() (fail_nth: 1)\n",
		lane + "r1 = syz_open_nfs_lane_profile$client0_knfsd_v41(0x3, 0x0)\n",
		lane + "r1 = syz_open_nfs_lane$client0(0x0)\n",
		"r0 = syz_open_nfs_lane_profile$client0_knfsd_v41(0x2, 0x1)\n",
	} {
		t.Run(source, func(t *testing.T) {
			if _, err := parseProgram(targetForTest(t), []byte(source)); err == nil {
				t.Fatal("accepted unsupported or malformed program")
			}
		})
	}
}

func TestAcquisitionAndDirectFD(t *testing.T) {
	source := lane + "fsync(r0)\nclose(r0)\nfsync(r0)\n"
	r := mustParse(t, source)
	if len(r.Acquisitions) != 1 || r.Acquisitions[0].Profile != "knfsd-v41" {
		t.Fatalf("acquisitions: %+v", r)
	}
	origin := "nfs-profile:knfsd-v41:client0"
	if r.Acquisitions[0].Origin != origin || r.Calls[1].Facts.Origins[0].Origin != origin {
		t.Fatal("wrong origin")
	}
	if len(r.Calls[3].Facts.Origins) != 0 {
		t.Fatal("closed descriptor retains origin")
	}
	if r.Usage != (usage{Bytes: len(source), Calls: 4, Resources: 4}) {
		t.Fatalf("usage: %+v", r.Usage)
	}
}

func TestLifecycleControlPreservesDirectFD(t *testing.T) {
	source := lane + "syz_nfsd_client_ctl$expire_client0(0x0)\nfsync(r0)\n"
	r := mustParse(t, source)
	if len(r.Calls) != 3 || len(r.Calls[2].Facts.Origins) != 1 {
		t.Fatalf("lifecycle control lost lane provenance: %+v", r)
	}
	if got := r.Calls[2].Facts.Origins[0].Origin; got != "nfs-profile:knfsd-v41:client0" {
		t.Fatalf("wrong origin after lifecycle control: %q", got)
	}
}

func TestCldControlPreservesDirectFD(t *testing.T) {
	source := lane + "syz_nfsd_client_ctl$expire_client0(0x0)\n" +
		"syz_nfsd_cld_ctl$reconnect(0x2)\nfsync(r0)\n"
	r := mustParse(t, source)
	if len(r.Calls) != 4 || len(r.Calls[3].Facts.Origins) != 1 {
		t.Fatalf("CLD control lost lane provenance: %+v", r)
	}
	if got := r.Calls[3].Facts.Origins[0].Origin; got != "nfs-profile:knfsd-v41:client0" {
		t.Fatalf("wrong origin after CLD control: %q", got)
	}
}

func TestAllExplicitProfiles(t *testing.T) {
	for p, suffix := range []string{"knfsd_v3", "knfsd_v40", "knfsd_v41", "knfsd_v42", "ganesha_v41"} {
		for client := 0; client < 2; client++ {
			source := fmt.Sprintf("r0 = syz_open_nfs_lane_profile$client%d_%s(0x%x, 0x%x)\nfsync(r0)\n", client, suffix, p, client)
			r := mustParse(t, source)
			if len(r.Acquisitions) != 1 || len(r.Calls[1].Facts.Origins) != 1 {
				t.Fatal("missing explicit acquisition")
			}
		}
	}
	// Both profiles must survive; Materializer rejects a mixed selection.
	r := mustParse(t, lane+"r1 = syz_open_nfs_lane_profile$client0_ganesha_v41(0x4, 0x0)\n")
	if len(r.Acquisitions) != 2 {
		t.Fatal("conflicting profile hidden")
	}
}

func TestUnprovedOrigins(t *testing.T) {
	for _, tail := range []string{
		"fsync(r0+1)\n", "fsync(r0/2)\n", "fsync(0x3)\n",
		"dup2(0x4, 0x5)\nfsync(r0)\n", "close_range(0x0, 0x100, 0x0)\nfsync(r0)\n",
		"r1 = openat$nfs_file(r0, &(0x7f0000000000)='./file\\x00', 0x0, 0x0)\nfsync(r1)\n",
	} {
		t.Run(tail, func(t *testing.T) {
			r := mustParse(t, lane+tail)
			if len(r.Calls[len(r.Calls)-1].Facts.Origins) != 0 {
				t.Fatal("fabricated origin")
			}
		})
	}
	r := mustParse(t, "# nfs-profile:knfsd-v41:client0\nfsync(0x3)\n")
	if len(r.Acquisitions) != 0 || len(r.Calls[0].Facts.Origins) != 0 {
		t.Fatal("comment trusted")
	}
}

func TestActualBufferAndIntegerFacts(t *testing.T) {
	r := mustParse(t, "write(0xffffffffffffffff, &(0x7f0000000000)=\"616263\", 0x3)\n")
	f := r.Calls[0].Facts
	if len(f.Bytes) != 1 || f.Bytes[0] != (byteFact{1, 3}) {
		t.Fatalf("bytes: %+v", f.Bytes)
	}
	if len(f.Integers) != 1 || f.Integers[0] != (integerFact{2, 3}) {
		t.Fatalf("integers: %+v", f.Integers)
	}
	if r.Usage.Resources != 3 {
		t.Fatalf("resource count excludes typed arguments: %+v", r.Usage)
	}
	r = mustParse(t, "nanosleep(&(0x7f0000000000)={0x0, 0x1}, 0x0)\n")
	if len(r.Calls[0].Facts.Bytes) != 0 {
		t.Fatal("aggregate pointer reported as byte buffer")
	}
	r = mustParse(t, "write(0xffffffffffffffff, &(0x7f0000000000)=\"61\", 0xffffffffffffffff)\n")
	if len(r.Calls[0].Facts.Integers) != 0 {
		t.Fatal("sign ambiguous integer claimed")
	}
}

func TestLimits(t *testing.T) {
	for _, data := range [][]byte{bytes.Repeat([]byte{'#'}, maxProgramBytes+1), []byte(strings.Repeat("getpid()\n", maxCalls+1))} {
		if _, err := parseProgram(targetForTest(t), data); err == nil {
			t.Fatal("limit not enforced")
		}
	}
	var output bytes.Buffer
	if err := writeJSON(&output, strings.Repeat("x", 128), 64); err == nil || output.Len() != 0 {
		t.Fatal("output limit not atomic")
	}
}

func TestTypedRefusals(t *testing.T) {
	for _, c := range []struct {
		source string
		want   refusal
	}{
		{"getpid()\n# c\n\nunknown_call()\n", refusal{"call_unresolved", 1, "unknown_call"}},
		{lane + "r1 = syz_not_in_build(0x0)\n", refusal{"call_unresolved", 1, "syz_not_in_build"}},
		{lane + "clone3(0x0, 0x0)\n", refusal{"call_disabled", 1, "clone3"}},
		{lane + "clone3 (0x0, 0x0)\n", refusal{"call_disabled", 1, "clone3"}},
		{lane + "clone3\t(0x0, 0x0)\n", refusal{"call_disabled", 1, "clone3"}},
		{lane + "syz_not_in_build ()\n", refusal{"call_unresolved", 1, "syz_not_in_build"}},
		{lane + "r1 =\tsyz_not_in_build\t()\n", refusal{"call_unresolved", 1, "syz_not_in_build"}},
		{lane + "r1 = syz_open_nfs_lane$client0(0x0)\n", refusal{"nfs_acquisition_unverified", 1, "syz_open_nfs_lane$client0"}},
	} {
		t.Run(c.source, func(t *testing.T) {
			_, err := parseProgram(targetForTest(t), []byte(c.source))
			var got *refusal
			if !errors.As(err, &got) || *got != c.want {
				t.Fatalf("got %v, want %+v", err, c.want)
			}
		})
	}
	// A malformed name or another strict error is not reported as typed.
	for _, source := range []string{"getpid(1)\n", "bad-name()\n"} {
		var got *refusal
		if _, err := parseProgram(targetForTest(t), []byte(source)); err == nil || errors.As(err, &got) {
			t.Fatalf("%q: %v", source, err)
		}
	}
}
