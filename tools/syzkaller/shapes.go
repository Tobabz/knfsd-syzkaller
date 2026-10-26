package main

import (
	"errors"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
)

// Argument shapes for the promotion criteria's argument-generality check
// (#100). A leaf is literal when the description admits one input value
// there (a constant, a one-value range or string), so every generated
// program carries the same literal. The walk fails closed: past the depth
// limit it refuses, and where a type recurs it records a recursive leaf
// rather than dropping what lies below.

const maxShapeCalls = 256
const maxShapeLeaves = 1 << 16
const maxShapeDepth = 32

type argumentLeaf struct {
	Path      string   `json:"path"`
	Literal   bool     `json:"literal"`
	Value     *uint64  `json:"value"`
	Text      *string  `json:"text"`
	Recursive bool     `json:"recursive"`
	Types     []string `json:"types"`
}

type callShape struct {
	Call   string         `json:"call"`
	Leaves []argumentLeaf `json:"leaves"`
}

type callShapes struct {
	Schema string      `json:"schema_version"`
	Commit string      `json:"syzkaller_commit"`
	Target string      `json:"target"`
	Calls  []callShape `json:"calls"`
}

type shapeWalker struct {
	leaves []argumentLeaf
}

func (w *shapeWalker) add(leaf argumentLeaf, types []string) error {
	if len(w.leaves) >= maxShapeLeaves {
		return errors.New("argument shape leaf limit exceeded")
	}
	leaf.Types = append([]string{}, types...)
	w.leaves = append(w.leaves, leaf)
	return nil
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// walk records the scalar positions below typ. Output positions carry no
// program literal.
func (w *shapeWalker) walk(typ prog.Type, dir prog.Dir, path string, types []string, depth int) error {
	if depth > maxShapeDepth {
		return errors.New("argument shape depth limit exceeded")
	}
	if dir == prog.DirOut {
		return nil
	}
	switch t := typ.(type) {
	case *prog.ConstType:
		if t.IsPad {
			return nil
		}
		v := t.Val
		return w.add(argumentLeaf{Path: path, Literal: true, Value: &v}, types)
	case *prog.IntType:
		if t.Kind == prog.IntRange && t.RangeBegin == t.RangeEnd {
			v := t.RangeBegin
			return w.add(argumentLeaf{Path: path, Literal: true, Value: &v}, types)
		}
		return w.add(argumentLeaf{Path: path}, types)
	case *prog.BufferType:
		if t.Kind == prog.BufferString && len(t.Values) == 1 {
			text := t.Values[0]
			return w.add(argumentLeaf{Path: path, Literal: true, Text: &text}, types)
		}
		return w.add(argumentLeaf{Path: path}, types)
	case *prog.PtrType:
		return w.walk(t.Elem, t.ElemDir, path, types, depth+1)
	case *prog.ArrayType:
		return w.walk(t.Elem, dir, path, types, depth+1)
	case *prog.StructType:
		return w.fields(t.Name(), t.Fields, dir, path, types, depth)
	case *prog.UnionType:
		return w.fields(t.Name(), t.Fields, dir, path, types, depth)
	default:
		// Flags (always 0 as well as their values), resources, lengths,
		// procs, vmas and checksums: chosen by syzkaller.
		return w.add(argumentLeaf{Path: path}, types)
	}
}

func (w *shapeWalker) fields(name string, fields []prog.Field, dir prog.Dir, path string, types []string, depth int) error {
	inner := append(append([]string{}, types...), name)
	for _, outer := range types {
		if outer == name {
			return w.add(argumentLeaf{Path: path, Recursive: true}, inner)
		}
	}
	for i := range fields {
		field := &fields[i]
		if err := w.walk(field.Type, field.Dir(dir), join(path, field.Name), inner, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func describeCalls(target *prog.Target, names []string) (callShapes, error) {
	if len(names) == 0 || len(names) > maxShapeCalls {
		return callShapes{}, errors.New("describe takes 1 to 256 calls")
	}
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	result := callShapes{"syz-call-shapes.v1", sourceCommit, targetName, nil}
	for i, name := range sorted {
		if i > 0 && sorted[i-1] == name {
			return callShapes{}, errors.New("duplicate call")
		}
		call := target.SyscallMap[name]
		if call == nil {
			return callShapes{}, errors.New("unresolved call")
		}
		walker := &shapeWalker{}
		for j := range call.Args {
			arg := &call.Args[j]
			if err := walker.walk(arg.Type, arg.Dir(prog.DirIn), arg.Name, nil, 0); err != nil {
				return callShapes{}, err
			}
		}
		if walker.leaves == nil {
			walker.leaves = []argumentLeaf{}
		}
		result.Calls = append(result.Calls, callShape{name, walker.leaves})
	}
	return result, nil
}

func callNames(data []byte) []string {
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	return names
}
