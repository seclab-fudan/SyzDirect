package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

const (
	callFileDir  = "call file dir"
	benchmarkDir = "benchmark dir"
)

func parseOutput() {
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		log.Fatalf("%v", err)
	}
	testIndexes := []uint32{106, 129, 131, 132, 133, 134, 140, 147, 153}

	callMap := make(map[uint32]prog.CallPairMap)
	for _, index := range testIndexes {
		callFile := path.Join(callFileDir, fmt.Sprintf("inp_%v.json", index))
		callMap[index] = prog.CallPairFromFile(callFile, target)
	}
	hitLog := make(prog.GlobalHitLog)
	for runIndex := 1; runIndex < 11; runIndex++ {
		logFile := path.Join(benchmarkDir, fmt.Sprintf("case%v", runIndex), "hitLog.json")
		rawData, err := os.ReadFile(logFile)
		if err != nil {
			log.Fatalf("open file %v err: %v", logFile, err)
		}
		tmpLog := make(prog.GlobalHitLog)
		err = json.Unmarshal(rawData, &tmpLog)
		if err != nil {
			log.Fatalf("unmarshal err %v", err)
		}
		for hitIdx, tmpItem := range tmpLog {
			storeItem := hitLog[hitIdx-1]
			storeItem.Progs = append(storeItem.Progs, tmpItem.Progs...)
			hitLog[hitIdx-1] = storeItem
		}
	}
	allCandidateCalls := make(map[uint32]map[string]int)
	for hitIdx, cpMap := range callMap {
		log.Printf("parsing index: %v\n", hitIdx)
		hitItem := hitLog[hitIdx]
		unfound := 0
		candidateCalls := make(map[string]int)
		for _, rawProg := range hitItem.Progs {
			p, err := target.Deserialize([]byte(rawProg), prog.NonStrict)
			if err != nil {
				log.Fatalf("deserialize prog %v err: %v\n", rawProg, err)
			}
			found := false
			for _, call := range p.Calls {
				if _, ok := cpMap[call.Meta.ID]; ok {
					found = true
					break
				}
			}
			if !found {
				for _, call := range p.Calls {
					candidateCalls[call.Meta.Name] += 1
				}
				unfound += 1
				log.Printf("dont contain target syscall\n%v", rawProg)
			}
		}
		allCandidateCalls[hitIdx] = candidateCalls
		log.Printf("index %v has prog %v, unfound target syscall %v", hitIdx, len(hitItem.Progs), unfound)
	}
	data, err := json.Marshal(allCandidateCalls)
	if err != nil {
		log.Fatalf("unmarshal err %v\n", err)
	}
	os.WriteFile("candidateCall.log", data, 0644)
}

type CallRelationItem struct {
	TCall int
	RCall int
	CCall int
}

type CallResource struct {
	inpResc  []*prog.ResultArg
	outResc  []*prog.ResultArg
	useFiles []string
}

func (resource *CallResource) isFileGenerator(meta *prog.Syscall) bool {
	return len(resource.useFiles) > 0 && prog.IsFileGenCallName(meta.Name)
}

func getArgString(data []byte, typ *prog.BufferType) string {
	val := string(data)
	// Remove trailing zero padding.
	for len(val) >= 2 && val[len(val)-1] == 0 && val[len(val)-2] == 0 {
		val = val[:len(val)-1]
	}
	switch typ.Kind {
	// case prog.BufferString:
	// 	s.strings[val] = true
	case prog.BufferFilename:
		if len(val) < 3 || escapingFilename(val) {
			// This is not our file, probalby one of specialFiles.
			return ""
		}
		if val[len(val)-1] == 0 {
			val = val[:len(val)-1]
		}
		return osutil.Abs(val)
	}
	return ""
}

func getCallResc(idx int, c *prog.Call, cache map[int]*CallResource) *CallResource {
	callResource, ok := cache[idx]
	if !ok {
		callResource = new(CallResource)
		prog.ForeachArg(c, func(arg prog.Arg, ctx *prog.ArgCtx) {
			switch typ := arg.Type().(type) {
			case *prog.ResourceType:
				a := arg.(*prog.ResultArg)
				if a.Dir() != prog.DirOut && a.Res != nil {
					callResource.inpResc = append(callResource.inpResc, a)
					// TODO: negative PIDs and add them as well (that's process groups).
				}
				if a.Dir() != prog.DirIn {
					callResource.outResc = append(callResource.outResc, a)
				}

			case *prog.BufferType:
				a := arg.(*prog.DataArg)
				if a.Dir() != prog.DirOut && len(a.Data()) != 0 {
					val := getArgString(a.Data(), typ)
					if val != "" {
						callResource.useFiles = append(callResource.useFiles, val)
					}
				}
			case *prog.StructType, *prog.UnionType:
				ctx.Stop = true
			}
		})
		cache[idx] = callResource
	}
	return callResource
}

func ExtractCallRelation(p *prog.Prog, callPairMap prog.CallPairMap) (res []CallRelationItem) {
	resourceCache := make(map[int]*CallResource)

	for i := len(p.Calls) - 1; i >= 0; i-- {
		targetCall := p.Calls[i]
		if _, ok := callPairMap[targetCall.Meta.ID]; !ok {
			continue
		}
		targetCallResource := getCallResc(i, targetCall, resourceCache)
		hasRCall := false
		if (len(targetCallResource.inpResc) == 0 && len(targetCallResource.useFiles) == 0) || targetCallResource.isFileGenerator(targetCall.Meta) {
			res = append(res, CallRelationItem{
				TCall: targetCall.Meta.ID,
				RCall: -1,
				CCall: -1,
			})
			// fmt.Println("this target syscall dont have input")
			continue
		}

		for j := 0; j < i; j++ {
			relateCall := p.Calls[j]
			relateCallResource := getCallResc(j, relateCall, resourceCache)
			if pairResource(relateCall.Meta, relateCallResource, targetCallResource) {
				hasRCall = true
				hasCCall := false
				for k := j + 1; k < i; k++ {
					contextCall := p.Calls[k]
					contextCallResource := getCallResc(j, contextCall, resourceCache)
					if pairResource(relateCall.Meta, relateCallResource, contextCallResource) {
						hasCCall = true
						res = append(res, CallRelationItem{
							TCall: targetCall.Meta.ID,
							RCall: relateCall.Meta.ID,
							CCall: contextCall.Meta.ID,
						})
					}
				}
				if !hasCCall {
					res = append(res, CallRelationItem{
						TCall: targetCall.Meta.ID,
						RCall: relateCall.Meta.ID,
						CCall: -1,
					})
				}
			}
		}
		if !hasRCall {
			res = append(res, CallRelationItem{
				TCall: targetCall.Meta.ID,
				RCall: -1,
				CCall: -1,
			})
			// fmt.Printf("raw prog: %v\ntarget syscall %v doesn't match!!! resource: %v", string(p.Serialize()), targetCall.Meta.Name, targetCallResource)
			continue
		}
	}
	return
}

func pairResource(outCallMeta *prog.Syscall, outCallResource, inpCallResource *CallResource) bool {
	for _, relateArg := range outCallResource.outResc {
		for _, targetArg := range inpCallResource.inpResc {
			if relateArg == targetArg.Res {
				return true
			}
		}
	}
	if len(inpCallResource.useFiles) > 0 && outCallResource.isFileGenerator(outCallMeta) {
		for _, relateStr := range outCallResource.useFiles {
			for _, targetStr := range inpCallResource.useFiles {
				if targetStr == relateStr {
					return true
				}
			}
		}
	}
	return false
}

func callid2Name(id int, target *prog.Target) string {
	if id == -1 {
		return "None"
	}
	return target.Syscalls[id].Name
}

func main() {
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		log.Fatalf("%v", err)
	}

	t2rMap, r2cMap := target.GenCallRelationData()
	return

	indexes := []int{44, 55, 57, 62, 68, 69, 73, 79, 95, 99, 105, 106, 130, 131, 132, 133, 139, 140, 147, 160, 161, 169, 185, 233, 236, 244, 248, 257}
	// indexes := []int{95}
	indexStats := make(map[int]*struct {
		InpTargetCallNum  int
		InpRelateCallNum  int
		InpContextCallNum int
		InpRelateRelNum   int
		InpContextRelNum  int

		ProgCount      int
		HasCallRelProg int
		TargetCallNum  int

		HasRelateProg        int
		RelateRelNum         int
		RelateRelDistinctNum int

		HasContextProg        int
		ContextRelNum         int
		ContextRelDistinctNum int

		RelateRelDistinctMarchNum  int
		QLie                       int
		RLie                       int
		ContextRelDistinctMarchNum int
		TLie                       int
		ULie                       int
	})
	var globalStat struct {
		InpTargetCallNum  int
		InpRelateCallNum  int
		InpContextCallNum int
		InpRelateRelNum   int
		InpContextRelNum  int

		ProgCount      int
		HasCallRelProg int
		TargetCallNum  int

		HasRelateProg        int
		RelateRelNum         int
		RelateRelDistinctNum int

		HasContextProg        int
		ContextRelNum         int
		ContextRelDistinctNum int

		RelateRelDistinctMarchNum  int
		QLie                       int
		RLie                       int
		ContextRelDistinctMarchNum int
		TLie                       int
		ULie                       int
	}
	indexStats[-1] = &globalStat
	gInpTargetCalls := make(map[int]bool)
	gInpRelateCalls := make(map[int]bool)
	gInpContextCalls := make(map[int]bool)
	gInpRelateRel := make(map[CallRelationItem]bool)
	gInpContextRel := make(map[CallRelationItem]bool)

	gTargetCalls := make(map[int]bool)
	gRelateRel := make(map[CallRelationItem]bool)
	gContextRel := make(map[CallRelationItem]bool)

	for _, index := range indexes {
		fmt.Printf("parsing index ---------%v-------\n", index)
		var currStat struct {
			InpTargetCallNum  int
			InpRelateCallNum  int
			InpContextCallNum int
			InpRelateRelNum   int // E
			InpContextRelNum  int

			ProgCount      int
			HasCallRelProg int
			TargetCallNum  int

			HasRelateProg        int
			RelateRelNum         int
			RelateRelDistinctNum int // L

			HasContextProg        int
			ContextRelNum         int
			ContextRelDistinctNum int

			RelateRelDistinctMarchNum  int // t
			QLie                       int // E - t
			RLie                       int // L -t
			ContextRelDistinctMarchNum int // m
			TLie                       int // F - m
			ULie                       int //
		}
		inpFile := fmt.Sprintf("../data/inp715/inp_%v.json", index)
		callPairMap := prog.CallPairFromFile(inpFile, target)
		inpRelateCalls := make(map[int]bool)
		inpContextCalls := make(map[int]bool)
		for tcall := range callPairMap {
			fmt.Printf("target call: %v\n", callid2Name(tcall, target))
			gInpTargetCalls[tcall] = true
			currStat.InpRelateRelNum += len(t2rMap[tcall])
			for _, rcall := range t2rMap[tcall] {
				inpRelateCalls[rcall] = true
				gInpRelateCalls[rcall] = true
				gInpRelateRel[CallRelationItem{tcall, rcall, -1}] = true
				currStat.InpContextRelNum += len(r2cMap[rcall])
				for _, ccall := range r2cMap[rcall] {
					gInpContextRel[CallRelationItem{tcall, rcall, ccall}] = true
					inpContextCalls[ccall] = true
					gInpContextCalls[ccall] = true
				}
			}
		}
		currStat.InpTargetCallNum = len(callPairMap)
		currStat.InpRelateCallNum = len(inpRelateCalls)
		currStat.InpContextCallNum = len(inpContextCalls)

		indexStats[index] = &currStat
		allTargetCalls := make(map[int]bool)
		allRelateRels := make(map[CallRelationItem]bool)
		allContextRels := make(map[CallRelationItem]bool)

		for i := 1; i < 6; i++ {
			hitLogFile := fmt.Sprintf("../workdir/701_patch/701_%v/case%v/hitLog.json", index, i)
			data, err := os.ReadFile(hitLogFile)
			if err != nil {
				log.Fatalf("read file %v: %v", hitLogFile, err)
			}
			var caseHitLog prog.GlobalHitLog
			err = json.Unmarshal(data, &caseHitLog)
			if err != nil {
				log.Fatalf("unmarshal err %v", err)
			}

			currStat.ProgCount += len(caseHitLog[uint32(index+1)].Progs)
			for _, rawProg := range caseHitLog[uint32(index+1)].Progs {
				p, err := target.Deserialize([]byte(rawProg), prog.NonStrict)
				if err != nil {
					log.Fatalf("deserialize prog: %v", err)
				}
				relItems := ExtractCallRelation(p, callPairMap)
				fmt.Printf("prog: %v\n", rawProg)
				if len(relItems) == 0 {
					fmt.Printf("\tdont extract item")
				} else {
					currStat.HasCallRelProg += 1
				}
				hasRelate := false
				hasContext := false
				for _, relItem := range relItems {
					fmt.Printf("extract rel item %v %v %v\n",
						callid2Name(relItem.TCall, target),
						callid2Name(relItem.RCall, target),
						callid2Name(relItem.CCall, target))
					allTargetCalls[relItem.TCall] = true
					gTargetCalls[relItem.TCall] = true
					if relItem.RCall != -1 {
						hasRelate = true
						currStat.RelateRelNum += 1
						allRelateRels[CallRelationItem{relItem.TCall, relItem.RCall, -1}] = true
						gRelateRel[CallRelationItem{relItem.TCall, relItem.RCall, -1}] = true
						if relItem.CCall != -1 {
							hasContext = true
							currStat.ContextRelNum += 1
							allContextRels[relItem] = true
							gContextRel[relItem] = true
						}
					}
				}
				if hasRelate {
					currStat.HasRelateProg += 1
					if hasContext {
						currStat.HasContextProg += 1
					}
				}
				fmt.Println()
			}
		}

		for relItem := range allRelateRels {
			matchStatus := "unmatch"
			if isInList(relItem.RCall, t2rMap[relItem.TCall]) {
				currStat.RelateRelDistinctMarchNum += 1
				matchStatus = "match"
			}
			fmt.Printf("\textract item 2 (%v) : tcall %v, rcall %v\n",
				matchStatus,
				callid2Name(relItem.TCall, target),
				callid2Name(relItem.RCall, target),
			)
		}
		for relItem := range allContextRels {
			matchStatus := "unmatch"
			if isInList(relItem.RCall, t2rMap[relItem.TCall]) &&
				isInList(relItem.CCall, r2cMap[relItem.RCall]) {
				currStat.ContextRelDistinctMarchNum += 1
				matchStatus = "match"
			}
			fmt.Printf("\textract item 3 (%v) : tcall %v, rcall %v, ccall %v\n",
				matchStatus,
				callid2Name(relItem.TCall, target),
				callid2Name(relItem.RCall, target),
				callid2Name(relItem.CCall, target),
			)
		}
		currStat.TargetCallNum = len(allTargetCalls)
		currStat.RelateRelDistinctNum = len(allRelateRels)
		currStat.ContextRelDistinctNum = len(allContextRels)
		currStat.QLie = currStat.InpRelateRelNum - currStat.RelateRelDistinctMarchNum
		currStat.RLie = currStat.RelateRelDistinctNum - currStat.RelateRelDistinctMarchNum
		currStat.TLie = currStat.InpContextRelNum - currStat.ContextRelDistinctMarchNum
		currStat.ULie = currStat.ContextRelDistinctNum - currStat.ContextRelDistinctMarchNum

		globalStat.ProgCount += currStat.ProgCount
		globalStat.HasCallRelProg += currStat.HasCallRelProg
		globalStat.HasRelateProg += currStat.HasRelateProg
		globalStat.HasContextProg += currStat.HasContextProg
		globalStat.RelateRelNum += currStat.RelateRelNum
		globalStat.ContextRelNum += currStat.ContextRelNum

		// data, err := json.MarshalIndent(currStat, "", "\t")
		// if err != nil {
		// 	fmt.Printf("marshal err: %v", err)
		// }
		// fmt.Printf("index %v data: %v\n", index, string(data))
	}

	globalStat.InpTargetCallNum = len(gInpTargetCalls)
	globalStat.InpRelateCallNum = len(gInpRelateCalls)
	globalStat.InpContextCallNum = len(gInpContextCalls)
	globalStat.InpRelateRelNum = len(gInpRelateRel)
	globalStat.InpContextRelNum = len(gInpContextRel)

	globalStat.TargetCallNum = len(gTargetCalls)
	globalStat.RelateRelDistinctNum = len(gRelateRel)
	globalStat.ContextRelDistinctNum = len(gContextRel)

	for relItem := range gRelateRel {
		if isInList(relItem.RCall, t2rMap[relItem.TCall]) {
			globalStat.RelateRelDistinctMarchNum += 1
		}
	}
	for relItem := range gContextRel {
		if isInList(relItem.RCall, t2rMap[relItem.TCall]) &&
			isInList(relItem.CCall, r2cMap[relItem.RCall]) {
			globalStat.ContextRelDistinctMarchNum += 1
		}
	}
	globalStat.QLie = globalStat.InpRelateRelNum - globalStat.RelateRelDistinctMarchNum
	globalStat.RLie = globalStat.RelateRelDistinctNum - globalStat.RelateRelDistinctMarchNum
	globalStat.TLie = globalStat.InpContextRelNum - globalStat.ContextRelDistinctMarchNum
	globalStat.ULie = globalStat.ContextRelDistinctNum - globalStat.ContextRelDistinctMarchNum

	data, err := json.MarshalIndent(indexStats, "", "\t")
	if err != nil {
		fmt.Printf("marshal err: %v", err)
	}
	err = os.WriteFile("stats2.json", data, 0644)
	if err != nil {
		fmt.Printf("write file err: %v", err)
	}
}

func isInList(a int, b []int) bool {
	for _, x := range b {
		if a == x {
			return true
		}
	}
	return false
}

func escapingFilename(file string) bool {
	file = filepath.Clean(file)
	return len(file) >= 1 && file[0] == '/' ||
		len(file) >= 2 && file[0] == '.' && file[1] == '.'
}
