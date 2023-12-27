package compiler

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func CompileInGo(desc *ast.Description, consts map[string]uint64, target *targets.Target, eh ast.ErrorHandler, constraintFile string, outDir string) *Prog {
	comp := createCompiler(desc.Clone(), target, eh)
	comp.filterArch()
	comp.typecheck()
	if comp.errors != 0 {
		return nil
	}
	if consts == nil {
		fileConsts := comp.extractConsts()
		if comp.errors != 0 {
			return nil
		}
		return &Prog{fileConsts: fileConsts}
	}
	if comp.target.SyscallNumbers {
		comp.assignSyscallNumbers(consts)
	}
	refiner := comp.CreateConstraintRefiner(constraintFile, consts)
	comp.patchConsts(consts)
	comp.check()
	if comp.errors != 0 {
		return nil
	}
	syscalls := comp.genSyscalls()
	comp.layoutTypes(syscalls)
	syscalls = refiner.GenerateRefinedCall(syscalls, outDir)
	types := comp.generateTypes(syscalls)
	prg := &Prog{
		Resources:   comp.genResources(),
		Syscalls:    syscalls,
		Types:       types,
		Unsupported: comp.unsupported,
	}
	if comp.errors != 0 {
		return nil
	}
	for _, w := range comp.warnings {
		eh(w.pos, w.msg)
	}
	return prg
}

const (
	ConstraintStringType  = "str"
	ConstraintIntType     = "int"
	ConstraintInvalidType = "invalid"

	CallThreshold = 10
)

type ConstraintItem struct {
	Value   uint64
	Name    string
	Type    string // "string" or "int"
	Syscall string
}

type CallRefiner struct {
	comp       *compiler
	renameMap  map[string]bool
	seen       map[prog.Type]prog.Type
	cstCallMap map[string][]string
	callNum    int

	strContainer   map[string]bool     // str name
	strucContainer map[string]int      // struc name: struc idx
	unionContainer map[string]int      // union name: choose idx
	flagContainer  map[string][]uint64 // flag name: const val
	callContainer  map[string]int      // call name: arg idx
	allContainer   map[string]bool     // just for check

	sourceTracer map[string][]string // new struc: constraint
}

func (comp *compiler) CreateConstraintRefiner(filename string, consts map[string]uint64) *CallRefiner {

	constraintItems := ParseConstraintInput(filename, consts)

	refiner := &CallRefiner{
		comp:           comp,
		renameMap:      make(map[string]bool),
		seen:           make(map[prog.Type]prog.Type),
		strContainer:   make(map[string]bool),
		strucContainer: make(map[string]int),
		unionContainer: make(map[string]int),
		flagContainer:  make(map[string][]uint64),
		callContainer:  make(map[string]int),
		allContainer:   make(map[string]bool),
		sourceTracer:   make(map[string][]string),
		cstCallMap:     make(map[string][]string),
	}
	callSet := make(map[string]struct{})
	for _, item := range constraintItems {
		switch item.Type {
		case ConstraintIntType:
			refiner.LocateConstContainer(item)
		case ConstraintStringType:
			refiner.strContainer[item.Name] = true
		}
		callSet[item.Syscall] = struct{}{}
		refiner.cstCallMap[item.Name] = append(refiner.cstCallMap[item.Name], item.Syscall)
	}

	refiner.callNum = len(callSet)

	for key := range refiner.strContainer {
		refiner.allContainer[key] = true
	}
	for key := range refiner.strucContainer {
		refiner.allContainer[key] = true
	}
	for key := range refiner.unionContainer {
		refiner.allContainer[key] = true
	}
	for key := range refiner.flagContainer {
		refiner.allContainer[key] = true
	}
	for key := range refiner.callContainer {
		refiner.allContainer[key] = true
	}
	return refiner
}

func (refiner *CallRefiner) GenerateRefinedCall(oriCalls []*prog.Syscall, outDir string) []*prog.Syscall {
	var (
		newArgs          []prog.Field
		targetContraints map[string]bool
	)
	refinedCalls := make(map[string][]string)

	for _, meta := range oriCalls {
		if _, ok := refiner.callContainer[meta.Name]; ok {
			log.Printf("is call!!")
		}
		newArgs = nil
		targetContraints = nil
		for i := range meta.Args {
			newType, sourceNames := refiner.genType(meta.Args[i].Type)
			if newType != nil {
				if newArgs == nil {
					newArgs = make([]prog.Field, len(meta.Args))
					copy(newArgs, meta.Args)
					targetContraints = make(map[string]bool)
				}
				newArgs[i].Type = newType
				sources := refiner.getTraceByType(newType)
				for _, source := range sources {
					targetContraints[source] = true
				}
			} else if len(sourceNames) > 0 {
				refiner.callContainer[meta.Name] = i
				for _, source := range sourceNames {
					refiner.addTraceByName(meta.Name, source, true)
				}
			}
		}
		if newArgs != nil {
			newMeta := *meta
			newMeta.Args = newArgs
			newMeta.Name = refiner.genNewName(meta.Name, true)
			csts := make([]string, 0, len(targetContraints))
			for k := range targetContraints {
				csts = append(csts, k)
			}
			refinedCalls[newMeta.Name] = csts
			oriCalls = append(oriCalls, &newMeta)
		}
	}

	for callName, idx := range refiner.callContainer {
		sources := refiner.getTraceByName(callName)
		log.Printf("constraint in call: %v:%v, source: %v", callName, idx, sources)
		refinedCalls[callName] = sources
	}

	if len(refinedCalls) > 0 {

		shouldStrict := refiner.callNum > CallThreshold || len(refinedCalls) > CallThreshold
		if shouldStrict {
			newRefinedCalls := make(map[string][]string)
			for refinedCall, csts := range refinedCalls {
				// if strings.HasSuffix(refinedCall, "") {

				// }
				isok := false
				for _, cst := range csts {
					sourceCalls := refiner.cstCallMap[cst]
					for _, sc := range sourceCalls {
						if strings.HasPrefix(refinedCall, sc) {
							newRefinedCalls[refinedCall] = csts
							isok = true
							break
						}
					}
					if isok {
						break
					}
				}
			}
			refinedCalls = newRefinedCalls
		}
		for refinedCall := range refinedCalls {
			log.Printf("gen new Call!! %v", refinedCall)
		}

		filePath := path.Join(outDir, "sys/linux/gen", "calltrace.json")
		data, err := json.Marshal(refinedCalls)
		if err != nil {
			log.Fatalf("unmarshal err %v", err)
		}
		err = os.WriteFile(filePath, data, 0644)
		if err != nil {
			log.Fatalf("write data err %v", err)
		}
	}

	sort.Slice(oriCalls, func(i, j int) bool {
		return oriCalls[i].Name < oriCalls[j].Name
	})
	return oriCalls
}

func (refiner *CallRefiner) addTraceByName(from string, to string, isInit bool) {
	var (
		toVals []string
		ok     bool
	)
	if toVals, ok = refiner.sourceTracer[to]; !ok {
		if !isInit {
			log.Fatalf("what???????????")
		}
		toVals = []string{to}
	}
	for _, toStr := range toVals {
		isExist := false
		for _, existStr := range refiner.sourceTracer[from] {
			if existStr == toStr {
				isExist = true
			}
		}
		if !isExist {
			refiner.sourceTracer[from] = append(refiner.sourceTracer[from], toStr)

		}
	}

}

func (refiner *CallRefiner) addTraceByType(from string, to prog.Type) {
	elem := to
	for shouldNext := true; shouldNext; {
		switch a := (elem).(type) {
		case *prog.PtrType:
			elem = a.Elem
		case *prog.ArrayType:
			elem = a.Elem
		default:
			shouldNext = false
		}
	}
	refiner.addTraceByName(from, elem.Name(), false)
}

func (refiner *CallRefiner) getTraceByType(from prog.Type) []string {
	elem := from
	for shouldNext := true; shouldNext; {
		switch a := (elem).(type) {
		case *prog.PtrType:
			elem = a.Elem
		case *prog.ArrayType:
			elem = a.Elem
		default:
			shouldNext = false
		}
	}
	return refiner.getTraceByName(elem.Name())
}

func (refiner *CallRefiner) getTraceByName(name string) []string {
	if constraints, ok := refiner.sourceTracer[name]; ok {
		return constraints
	}
	panic("cannot locate source!!")
}

func (refiner *CallRefiner) genType(t0 prog.Type) (prog.Type, []string) {
	var sourceNames []string
	var rec func(prog.Type) prog.Type
	recPath := make(map[prog.Type]bool)

	rec = func(ptr prog.Type) prog.Type {
		name := ptr.Name()
		switch a := (ptr).(type) {
		case *prog.PtrType:
			newElem := rec(a.Elem)
			if newElem != nil {
				newArg := *a
				newArg.Elem = newElem
				return &newArg
			}
		case *prog.ArrayType:
			newElem := rec(a.Elem)
			if newElem != nil {
				newArg := *a
				newArg.Elem = newElem
				return &newArg
			}
		case *prog.StructType:
			if parsedType, ok := refiner.seen[a]; ok {
				return parsedType
			}
			idx, inContainer := refiner.strucContainer[name]
			if inContainer {
				log.Printf("found struc container, %v %v\n", name, idx)
			}
			if recPath[a] {
				break
			}
			recPath[a] = true
			var newFields []prog.Field
			var newName string
			for i := range a.Fields {
				newElem := rec(a.Fields[i].Type)
				if newElem != nil {
					if newFields == nil {
						newFields = make([]prog.Field, len(a.Fields))
						copy(newFields, a.Fields)
						newName = refiner.genNewName(name, false)
					}
					newFields[i].Type = newElem
					refiner.addTraceByType(newName, newElem)
				}
			}
			delete(recPath, a)
			refiner.seen[a] = nil
			if newFields != nil {
				if inContainer {
					refiner.addTraceByType(newName, a)
				}
				newArg := *a
				newArg.Fields = newFields
				newArg.TypeName = newName
				refiner.seen[a] = &newArg
				return &newArg
			}
			if inContainer {
				refiner.seen[a] = a
				return a
			}
		case *prog.UnionType:
			if parsedType, ok := refiner.seen[a]; ok {
				return parsedType
			}
			idx, inContainer := refiner.unionContainer[name]
			if inContainer {
				log.Printf("found union container, %v %v\n", name, idx)
			}
			if recPath[a] {
				break
			}
			recPath[a] = true
			var newFields []prog.Field
			var newName string
			for i := range a.Fields {
				newElem := rec(a.Fields[i].Type)
				inTrace := false
				if inContainer && i == idx && newElem == nil {
					newElem = a.Fields[i].Type
					inTrace = true
				}
				if newElem != nil {
					if newName == "" {
						newName = refiner.genNewName(name, false)
					}
					newField := a.Fields[i]
					newField.Type = newElem
					newFields = append(newFields, newField)
					if !inTrace {
						refiner.addTraceByType(newName, newElem)
					} else {
						refiner.addTraceByType(newName, a)
					}
				}
			}
			delete(recPath, a)
			refiner.seen[a] = nil
			if len(newFields) > 0 {
				newArg := *a
				newArg.Fields = newFields
				newArg.TypeName = newName
				refiner.seen[a] = &newArg
				return &newArg
			}
		case *prog.FlagsType:
			if inpVals, ok := refiner.flagContainer[name]; ok {
				if len(a.Vals) == len(inpVals) {
					allEqual := true
					for i := range a.Vals {
						if a.Vals[i] != inpVals[i] {
							allEqual = false
						}
					}
					if allEqual {
						sourceNames = refiner.getTraceByName(name)
						return a
					}
				}
				newArg := *a
				newArg.Vals = inpVals
				return &newArg
			}
		case *prog.BufferType:
			if a.Kind == prog.BufferString || a.Kind == prog.BufferGlob {
				var newValues []string
				for j, v := range a.Values {
					for v != "" && v[len(v)-1] == 0 {
						v = v[:len(v)-1]
					}
					if refiner.strContainer[v] {
						newValues = append(newValues, a.Values[j])
						refiner.addTraceByName(name, v, true)
					}
				}
				if len(newValues) > 0 {
					if len(newValues) == len(a.Values) {
						sourceNames = refiner.getTraceByName(name)
						return a
					}
					newArg := *a
					newArg.Values = newValues
					return &newArg
				}
			}
		case *prog.ResourceType, *prog.VmaType, *prog.LenType, *prog.ConstType, *prog.IntType, *prog.ProcType, *prog.CsumType:
		default:
			panic("unknown type")
		}
		if refiner.allContainer[name] {
			log.Fatalf("what ???? catch unhandle container %v", name)
		}
		return nil
	}
	return rec(t0), sourceNames
}

func (refiner *CallRefiner) genNewName(oriName string, isCall bool) string {
	suffix := "_rf"
	if isCall && !strings.Contains(oriName, "$") {
		suffix = "$tmp_rf"
	}
	var newName string
	for i := 1; ; i++ {
		newName = fmt.Sprintf("%v%v%v", oriName, suffix, i)
		if !refiner.renameMap[newName] {
			break
		}
		refiner.renameMap[newName] = true
	}
	return newName
}

func (refiner *CallRefiner) LocateConstContainer(constItem ConstraintItem) {
	comp := refiner.comp
	var (
		traces    [][]string
		currTrace []string
		rec       func(t *ast.Type, isArg bool) bool
	)
	constName := constItem.Name
	identHandler := func(id string) bool {
		if id == constName {
			if len(currTrace) > 3 && currTrace[2] == "check" {
				log.Fatalf("uncertain trace of %v, should check %v\n", constName, currTrace)
			}
			currTraceCopy := make([]string, len(currTrace)+1)
			copy(currTraceCopy, currTrace)
			currTraceCopy = append(currTraceCopy, id)
			traces = append(traces, currTraceCopy)
			return true
		}
		return false
	}

	typeHandler := func(n *ast.Type) bool {
		if identHandler(n.Ident) {
			return true
		}
		currTrace = append(currTrace, n.Ident)
		found := false
		for _, col := range n.Colon {
			found = found || identHandler(col.Ident)
		}
		currTrace = currTrace[:len(currTrace)-1]
		return found
	}

	rec = func(t *ast.Type, isArg bool) bool {
		desc, args, _ := comp.getArgsBase(t, isArg)
		currTrace = append(currTrace, t.Ident)
		found := false
		for i, arg := range args {
			if desc.Args[i].Type == typeArgType {
				found = found || rec(arg, desc.Args[i].IsArg)
			}
			if desc.Args[i].Type.Kind == kindInt {
				found = found || typeHandler(arg)
			}
		}
		currTrace = currTrace[:len(currTrace)-1]
		return found
	}

	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.IntFlags:
			currTrace = []string{"flags", n.Name.Name}
			for _, v := range n.Values {
				if identHandler(v.Ident) {
					refiner.flagContainer[n.Name.Name] = append(refiner.flagContainer[n.Name.Name], constItem.Value)
					refiner.addTraceByName(n.Name.Name, constItem.Name, true)
				}
			}
		case *ast.Call:
			currTrace = []string{"call", n.Name.Name}
			for i, arg := range n.Args {
				if rec(arg.Type, true) {
					if oldVal, ok := refiner.callContainer[n.Name.Name]; ok {
						log.Fatalf("same call container: %v, old: %v, const: %v", n.Name.Name, oldVal, constName)
					}
					refiner.callContainer[n.Name.Name] = i
					refiner.addTraceByName(n.Name.Name, constItem.Name, true)
				}
			}
			currTrace = append(currTrace, "check")
			if n.Ret != nil {
				rec(n.Ret, true)
			}
			for _, attr := range n.Attrs {
				if callAttrs[attr.Ident].HasArg {
					typeHandler(attr.Args[0])
				}
			}
		case *ast.Resource:
			currTrace = []string{"resource", n.Name.Name, "check"}
			rec(n.Base, false)
			for _, v := range n.Values {
				identHandler(v.Ident)
			}
		case *ast.Struct:
			prefix := "struct"
			if n.IsUnion {
				prefix = "union"
				currTrace = []string{"union", n.Name.Name, "check"}
			} else {
				currTrace = []string{"struct", n.Name.Name}
			}
			for i, f := range n.Fields {
				if rec(f.Type, false) {
					targetMap := refiner.strucContainer
					if n.IsUnion {
						targetMap = refiner.unionContainer
					}
					if oldVal, ok := targetMap[n.Name.Name]; ok {
						log.Fatalf("same %v container: %v, old: %v, const: %v", prefix, n.Name.Name, oldVal, constName)
					}
					targetMap[n.Name.Name] = i
					refiner.addTraceByName(n.Name.Name, constItem.Name, true)
				}
			}
			currTrace = append(currTrace, "check")
			for _, attr := range n.Attrs {
				if structOrUnionAttrs(n)[attr.Ident].HasArg {
					typeHandler(attr.Args[0])
				}
			}
		case *ast.TypeDef:
			if len(n.Args) == 0 {
				currTrace = []string{"typedef", n.Name.Name, "check"}
				rec(n.Type, false)
			}
		}
	}
	log.Printf("%v trace: %v", constName, traces)
}

func ParseConstraintInput(filename string, consts map[string]uint64) []ConstraintItem {
	var items []ConstraintItem
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("read const file %v err: %v\n", filename, err)
	}
	err = json.Unmarshal(data, &items)
	if err != nil {
		log.Fatalf("unmarshal err %v\n", err)
	}
	res := make([]ConstraintItem, 0, len(items))
	for _, item := range items {
		switch item.Type {
		case ConstraintInvalidType:
			continue
		case ConstraintStringType:
			res = append(res, item)
		case ConstraintIntType:
			if syzVal, ok := consts[item.Name]; !ok {
				log.Printf("const not found: %v\n", item.Name)
			} else if syzVal != item.Value {
				log.Printf("const %v val not match, expect %v (got %v)\n", item.Name, syzVal, item.Value)
			} else {
				res = append(res, item)
			}
		default:
			log.Fatalf("unsupported const type %v\n", item.Type)
		}
	}
	return res
}
