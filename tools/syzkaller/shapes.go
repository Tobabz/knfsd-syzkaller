package main

import (
	"errors"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
)

// Argument shapes for the promotion criteria's argument-generality check
// (#100). A leaf is literal when the description admits one input value
// there, so every generated program carries the same literal.

const maxShapeCalls = 256
const maxShapeLeaves = 1 << 16
const maxShapeDepth = 32

type argumentLeaf struct {
	Path    string   `json:"path"`
	Literal bool     `json:"literal"`
	Value   *uint64  `json:"value"`
	Types   []string `json:"types"`
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

func (w *shapeWalker) add(path string, types []string, literal bool, value *uint64) error {
	if len(w.leaves) >= maxShapeLeaves {
		return errors.New("argument shape leaf limit exceeded")
	}
	w.leaves = append(w.leaves, argumentLeaf{path, literal, value, append([]string{}, types...)})
	return nil
}

func number(v uint64) *uint64 {
	return &v
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// walk records the scalar positions below typ. Output positions carry no
// program literal; recursive types stop at the first repetition.
func (w *shapeWalker) walk(typ prog.Type, dir prog.Dir, path string, types []string, depth int) error {
	if depth > maxShapeDepth {
		return nil
	}
	if dir == prog.DirOut {
		return nil
	}
	switch t := typ.(type) {
	case *prog.ConstType:
		if t.IsPad {
			return nil
		}
		return w.add(path, types, true, number(t.Val))
	case *prog.FlagsType:
		if len(t.Vals) == 1 {
			return w.add(path, types, true, number(t.Vals[0]))
		}
		return w.add(path, types, false, nil)
	case *prog.IntType:
		if t.Kind == prog.IntRange && t.RangeBegin == t.RangeEnd {
			return w.add(path, types, true, number(t.RangeBegin))
		}
		return w.add(path, types, false, nil)
	case *prog.BufferType:
		if t.Kind == prog.BufferString && len(t.Values) == 1 {
			// A fixed string is a literal without a numeric value.
			return w.add(path, types, true, nil)
		}
		return w.add(path, types, false, nil)
	case *prog.PtrType:
		return w.walk(t.Elem, t.ElemDir, path, types, depth+1)
	case *prog.ArrayType:
		return w.walk(t.Elem, dir, path, types, depth+1)
	case *prog.StructType:
		for _, name := range types {
			if name == t.Name() {
				return nil
			}
		}
		inner := append(append([]string{}, types...), t.Name())
		for i := range t.Fields {
			field := &t.Fields[i]
			if err := w.walk(field.Type, field.Dir(dir), join(path, field.Name), inner, depth+1); err != nil {
				return err
			}
		}
		return nil
	case *prog.UnionType:
		for _, name := range types {
			if name == t.Name() {
				return nil
			}
		}
		inner := append(append([]string{}, types...), t.Name())
		for i := range t.Fields {
			field := &t.Fields[i]
			if err := w.walk(field.Type, field.Dir(dir), join(path, field.Name), inner, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		// Resources, lengths, procs, vmas, checksums: chosen by syzkaller.
		return w.add(path, types, false, nil)
	}
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
