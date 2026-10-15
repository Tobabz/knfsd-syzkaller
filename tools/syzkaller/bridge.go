// The bridge is built in the pinned, patched syzkaller module. No guest code runs.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// Set by the builder, not by a parse request.
var sourceCommit, patchDigest, sourceTree string
var targetName = "linux/amd64"

const maxProgramBytes = 256 << 10
const maxOutputBytes = 16 << 20
const maxCalls = 4096
const maxResources = 65536

type bridgeInfo struct {
	Schema string `json:"schema_version"`
	Commit string `json:"syzkaller_commit"`
	Patch  string `json:"patch_series_sha256"`
	Tree   string `json:"source_tree"`
	Target string `json:"target"`
}

func metadata() bridgeInfo {
	return bridgeInfo{"knfsd-syz-bridge.v1", sourceCommit, patchDigest, sourceTree, targetName}
}

type callTable struct {
	Schema string   `json:"schema_version"`
	Commit string   `json:"syzkaller_commit"`
	Target string   `json:"target"`
	Calls  []string `json:"calls"`
}

func exportTable(target *prog.Target) callTable {
	names := make([]string, 0, len(target.Syscalls))
	for _, call := range target.Syscalls {
		names = append(names, call.Name)
	}
	sort.Strings(names)
	return callTable{"syzkaller-call-table.v1", sourceCommit, targetName, names}
}

func run(args []string, input io.Reader, output io.Writer) error {
	if len(args) != 1 || (args[0] != "export" && args[0] != "parse") {
		return errors.New("expected export or parse")
	}
	if len(sourceCommit) != 40 || len(patchDigest) != 64 || len(sourceTree) != 40 || targetName != "linux/amd64" {
		return errors.New("missing or unsupported compiled build identity")
	}
	parts := strings.Split(targetName, "/")
	target, err := prog.GetTarget(parts[0], parts[1])
	if err != nil {
		return err
	}
	var result any
	if args[0] == "export" {
		result = struct {
			Bridge bridgeInfo `json:"bridge"`
			Table  callTable  `json:"call_table"`
		}{metadata(), exportTable(target)}
	} else {
		data, err := io.ReadAll(io.LimitReader(input, maxProgramBytes+1))
		if err != nil {
			return err
		}
		if len(data) > maxProgramBytes {
			return errors.New("program byte limit exceeded")
		}
		parsed, err := parseProgram(target, data)
		if err != nil {
			return err
		}
		result = struct {
			Bridge  bridgeInfo    `json:"bridge"`
			Program programResult `json:"program"`
		}{metadata(), parsed}
	}
	return writeJSON(output, result, maxOutputBytes)
}

func writeJSON(output io.Writer, result any, limit int) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(data) > limit {
		return errors.New("output byte limit exceeded")
	}
	_, err = output.Write(data)
	return err
}

func main() {
	debug.SetMemoryLimit(256 << 20)
	// A short textual program can request many large DataArg allocations.
	// GOMEMLIMIT is only a GC target; RLIMIT_AS is the hard backstop.
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: 2 << 30, Max: 2 << 30}); err != nil {
		os.Exit(2)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 20, Max: 20}); err != nil {
		os.Exit(2)
	}
	// The caller also imposes a wall timeout and bounded stdout/stderr. Avoid
	// reflecting attacker-controlled source or huge parser diagnostics in errors.
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		// A typed refusal goes out as one bounded JSON object, exit 3.
		var typed *refusal
		if errors.As(err, &typed) {
			if data, jerr := json.Marshal(typed); jerr == nil {
				os.Stderr.Write(append(data, '\n'))
				os.Exit(3)
			}
		}
		message := err.Error()
		if len(message) > 1024 {
			message = message[:1024]
		}
		fmt.Fprintln(os.Stderr, message)
		os.Exit(1)
	}
}
