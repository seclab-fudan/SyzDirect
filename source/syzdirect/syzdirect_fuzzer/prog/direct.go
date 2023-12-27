package prog

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

const (
	InvalidDist        uint32 = 0xFFFFFFFF
	MaxDist            uint32 = 30000
	CallPairInitNum    int    = 20
	CallPairLimitMulti uint32 = 2
)

type CallPairMap map[int][]int

type CallPairInfo struct {
	Tcall int
	Rcall int
	Dists []uint32
	// DistSum uint32
	Prio int
}

type RpcCallPairMap map[int]map[int][]uint32

type RawCallPair struct {
	Target string
	Relate []string
}

type RpcCallHitTime struct {
	CallId int
	Since  time.Duration
}

type CallPairSelector struct {
	hitIndex          uint32
	prioSum           int
	lastHitDataUpdate time.Time

	isUpdated     bool
	callPairInfos []CallPairInfo
	infoIdxMap    map[int]map[int]int

	// targetCalls []int

	// newcpMap RpcCallPairMap
	mu sync.RWMutex
}

func (ct *ChoiceTable) EnableGo(cpMap CallPairMap, rpcCPMap RpcCallPairMap, corpus []*Prog, startTime time.Time, hitIndex uint32) {
	cpInfos := make([]CallPairInfo, 0, len(cpMap)*3)
	infoIdxMap := make(map[int]map[int]int, len(cpMap))
	allPrio := 0
	// targetCalls := make([]int, 0, len(cpMap))
	for tcall, rcalls := range cpMap {
		if !ct.Enabled(tcall) {
			continue
		}
		rpcRcallMap, ok1 := rpcCPMap[tcall]
		tmp := append(rcalls, -1)
		rIdxMap := make(map[int]int)
		for _, rcall := range tmp {
			if rcall != -1 && !ct.Enabled(rcall) {
				continue
			}
			hasAdd := false
			if ok1 {
				if dists2, ok2 := rpcRcallMap[rcall]; ok2 {
					prio := distance2Prio(calcDistSum(dists2), len(dists2))
					cpInfos = append(cpInfos, CallPairInfo{
						Tcall: tcall,
						Rcall: rcall,
						Prio:  prio,
						Dists: dists2,
					})
					allPrio += prio
					hasAdd = true
				}
			}
			if !hasAdd {
				prio := 1
				if rcall == -1 {
					prio = 0
				}
				cpInfos = append(cpInfos, CallPairInfo{
					Tcall: tcall,
					Rcall: rcall,
					Prio:  prio,
					Dists: make([]uint32, 0, 5),
				})
				allPrio += prio
			}
			rIdxMap[rcall] = len(cpInfos) - 1
		}
		// targetCalls = append(targetCalls, tcall)
		infoIdxMap[tcall] = rIdxMap
	}
	if len(cpInfos) == 0 {
		panic("all target calls are disabled")
	}

	ct.GoEnable = true
	ct.startTime = startTime
	ct.CallPairSelector.hitIndex = hitIndex
	ct.CallPairSelector.callPairInfos = cpInfos
	ct.CallPairSelector.prioSum = allPrio
	ct.CallPairSelector.infoIdxMap = infoIdxMap
	// ct.CallPairSelector.newcpMap = make(RpcCallPairMap, len(infoIdxMap))
}

func (selector *CallPairSelector) UpdateCallDistance(p *Prog, dist uint32) {
	if dist == InvalidDist {
		return
	}
	selector.mu.Lock()
	defer selector.mu.Unlock()
	tcallId := p.Tcall.Meta.ID
	rcallId := -1
	if p.Rcall != nil {
		rcallId = p.Rcall.Meta.ID
	}
	infoIdx := selector.infoIdxMap[tcallId][rcallId]
	info := &selector.callPairInfos[infoIdx]
	dists := info.Dists
	idx, shouldRet := locateIndex(dists, dist)
	if shouldRet {
		return
	}
	prevDistSum := calcDistSum(dists)
	if idx == len(dists) {
		dists = append(dists, dist)
	} else {
		if len(dists) >= 5 {
			dists = dists[:4]
		}
		if idx == 0 {
			right := len(dists) - 1
			for right >= 0 && 2*dist < dists[right] {
				right--
			}
			if right >= 0 {
				dists = append([]uint32{dist}, dists[:right+1]...)
			} else {
				dists = []uint32{dist}
			}
		} else {
			tmp := append([]uint32{dist}, dists[idx:]...)
			dists = append(dists[:idx], tmp...)
		}
	}
	currDistSum := calcDistSum(dists)
	info.Dists = dists
	if prevDistSum != currDistSum {
		selector.prioSum = selector.prioSum - info.Prio
		info.Prio = distance2Prio(currDistSum, len(info.Dists))
		selector.prioSum += info.Prio
		// if _, ok := selector.newcpMap[tcallId]; !ok {
		// 	selector.newcpMap[tcallId] = make(map[int][]uint32)
		// }
		// selector.newcpMap[tcallId][rcallId] = dists
		selector.isUpdated = true
	}
}

func locateIndex(dists []uint32, dist uint32) (int, bool) {
	idx := len(dists) - 1
	for idx >= 0 {
		if dists[idx] > dist {
			idx -= 1
		} else {
			break
		}
	}
	idx += 1
	if idx >= 5 || (len(dists) > 0 && CallPairLimitMulti*dists[0] < dist) {
		return idx, true
	}
	return idx, false
}

type CPLogItem struct {
	Progs map[int]string
	Dists []uint32
}

type ManagerCallPairRecorder map[int]map[int]CPLogItem

func (recorder ManagerCallPairRecorder) HandlerProgDist(prog []byte, dist uint32, tcall, rcall int) {
	rMap, ok := recorder[tcall]
	if !ok {
		rMap = make(map[int]CPLogItem)
		recorder[tcall] = rMap
	}
	item, ok2 := rMap[rcall]
	if !ok2 {
		item.Progs = make(map[int]string, 5)
		item.Dists = make([]uint32, 0, 5)
	}
	idx, shouldRet := locateIndex(item.Dists, dist)
	if shouldRet {
		return
	}
	if idx == len(item.Dists) {
		item.Dists = append(item.Dists, dist)
	} else {
		if len(item.Dists) >= 5 {
			item.Dists = item.Dists[:4]
		}
		if idx == 0 {
			right := len(item.Dists) - 1
			for right >= 0 && 2*dist < item.Dists[right] {
				right--
			}
			if right >= 0 {
				item.Dists = append([]uint32{dist}, item.Dists[:right+1]...)
			} else {
				item.Dists = []uint32{dist}
			}
		} else {
			tmp := append([]uint32{dist}, item.Dists[idx:]...)
			item.Dists = append(item.Dists[:idx], tmp...)
		}
	}
	item.Progs[idx] = string(prog)
	rMap[rcall] = item
}

func (recorder ManagerCallPairRecorder) ToRpcCallPair() RpcCallPairMap {
	rpcCPmap := make(RpcCallPairMap, len(recorder))
	for tcall, rcallMap := range recorder {
		tmp := make(map[int][]uint32, len(rcallMap))
		for rcall, rcallItem := range rcallMap {
			tmp[rcall] = rcallItem.Dists
		}
		rpcCPmap[tcall] = tmp
	}
	return rpcCPmap
}

func (recorder ManagerCallPairRecorder) CustomMarshal(target *Target, uptime time.Duration) []byte {
	logStruct := struct {
		Uptime   int64
		LogItems map[string]map[string]CPLogItem
	}{
		Uptime:   int64(uptime),
		LogItems: make(map[string]map[string]CPLogItem),
	}
	for tcall, rcallMap := range recorder {
		tcallName := target.Syscalls[tcall].Name
		rcallLogMap := make(map[string]CPLogItem, len(rcallMap))
		for rcall, logItem := range rcallMap {
			rcallName := "none"
			if rcall > 0 && rcall < len(target.Syscalls) {
				rcallName = target.Syscalls[rcall].Name
			}
			rcallLogMap[rcallName] = logItem
		}
		logStruct.LogItems[tcallName] = rcallLogMap
	}
	data, err := json.MarshalIndent(logStruct, "", "\t")
	if err != nil {
		log.Fatalf("marshal err %v\n", err)
	}
	return data
}

func (selector *CallPairSelector) SelectCallPair(r *rand.Rand) (int, int) {
	selector.mu.RLock()
	defer selector.mu.RUnlock()
	if selector.prioSum == 0 {
		idx := r.Intn(len(selector.callPairInfos))
		info := &selector.callPairInfos[idx]
		return info.Tcall, info.Rcall
	}
	randVal := r.Intn(selector.prioSum)
	for i := range selector.callPairInfos {
		info := &selector.callPairInfos[i]
		if info.Prio > randVal {
			return info.Tcall, info.Rcall
		}
		randVal -= info.Prio
	}
	log.Fatalf("what ??????")
	return -1, -1
}

// func (selector *CallPairSelector) GetDeltaCPMap() RpcCallPairMap {
// 	if time.Since(selector.lastHitDataUpdate) < 5*time.Minute {
// 		return nil
// 	}
// 	selector.mu.Lock()
// 	defer selector.mu.Unlock()
// 	if len(selector.newcpMap) == 0 {
// 		return nil
// 	}
// 	tmp := selector.newcpMap
// 	selector.newcpMap = make(RpcCallPairMap, len(selector.infoIdxMap))
// 	selector.lastHitDataUpdate = time.Now()
// 	return tmp
// }

func calcDistSum(dists []uint32) uint32 {
	distSum := uint32(0)
	for _, d := range dists {
		distSum += d
	}
	return distSum
}

func distance2Prio(distSum uint32, distSize int) int {
	var prio int
	dist := float64(distSum) / float64(distSize)
	if dist < 1000 {
		prio = int(1000 * math.Exp(dist*(-0.002)))
	} else {
		left, right := 0.0, 0.0
		switch int(dist / 1000) {
		case 1:
			left, right = 135, 48
		case 2:
			left, right = 48, 16
		case 3:
			left, right = 16, 8
		case 4:
			left, right = 8, 4
		case 5:
			left, right = 4, 2
		}
		if left == right {
			prio = 1
		} else {
			prio = int(left - (left-right)*(float64(int(dist)%1000))/1000.0)
		}
	}
	return prio
}

func CallPairFromFile(filename string, target *Target) CallPairMap {
	if filename == "" {
		return nil
	}
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("open callfile %v with err: %v\n", filename, err)
		return nil
	}
	var rawCallPairs []RawCallPair
	err = json.Unmarshal(b, &rawCallPairs)
	if err != nil {
		log.Fatalf("call pair unmarshal file %v err: %v\n", filename, err)
	}

	str2Calls := func(call string) []int {
		var res []int
		for _, meta := range target.Syscalls {
			if matchSyscall(meta.Name, call) {
				res = append(res, meta.ID)
			}
		}
		if len(res) == 0 {
			log.Printf("unknown input call:%v\n", call)
		}
		return res
	}

	tmpCallMap := make(map[int]map[int]bool, len(rawCallPairs))
	for _, rawCallPair := range rawCallPairs {
		tcalls := str2Calls(rawCallPair.Target)
		for _, tcall := range tcalls {
			rcallMap := tmpCallMap[tcall]
			if rcallMap == nil {
				rcallMap = make(map[int]bool, len(rawCallPair.Relate))
				tmpCallMap[tcall] = rcallMap
			}
			for _, rawRCall := range rawCallPair.Relate {
				for _, rc := range str2Calls(rawRCall) {
					rcallMap[rc] = true
				}
			}
		}
	}
	callPairMap := make(CallPairMap, len(tmpCallMap))
	for tcall, rcallMap := range tmpCallMap {
		keys := make([]int, 0, len(rcallMap))
		for k := range rcallMap {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i] < keys[j]
		})
		callPairMap[tcall] = keys
	}
	return callPairMap
}

func (cpMap CallPairMap) GetRawTargetCalls(target *Target) map[int]bool {
	rawTcalls := make(map[int]bool, len(cpMap))
	for tcall := range cpMap {
		callName := target.Syscalls[tcall].Name
		if strings.HasSuffix(callName, "_rf1") {
			oriName := callName[:len(callName)-4]
			if strings.HasSuffix(callName, "$tmp_rf1") {
				oriName = callName[:len(callName)-8]
			}
			rawTcalls[target.SyscallMap[oriName].ID] = true
		} else {
			rawTcalls[tcall] = true
		}
	}
	return rawTcalls
}

func matchSyscall(name, pattern string) bool {
	if pattern == name {
		return true
	}
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' &&
		strings.HasPrefix(name, pattern[:len(pattern)-1]) {
		return true
	}
	return false
}

type ProgHitCountItem struct {
	Count   uint32
	CallIds []int
}

type ProgHitCounts map[uint32]ProgHitCountItem

type HitLogItem struct {
	Count        uint32
	HitCalls     []int
	FirstHitTime time.Duration
	Progs        []string
}

type GlobalHitLog map[uint32]HitLogItem

func (progHitCount ProgHitCounts) MergeHitCount(hitArr []uint32, callId int) {
	if len(hitArr)%2 != 0 {
		log.Fatalf("hit array not dual %v", hitArr)
	}
	for i := 0; i < len(hitArr); i += 2 {
		hitItem := progHitCount[hitArr[i]]
		hitItem.Count += hitArr[i+1]
		hitItem.CallIds = append(hitItem.CallIds, callId)
		progHitCount[hitArr[i]] = hitItem
	}
}

func (item *HitLogItem) AddCallIds(callids []int) {
	for _, newCallid := range callids {
		hasRecord := false
		for _, oldCallid := range item.HitCalls {
			if oldCallid == newCallid {
				hasRecord = true
				break
			}
		}
		if !hasRecord {
			item.HitCalls = append(item.HitCalls, newCallid)
		}
	}
}

func (hitLog GlobalHitLog) CustomMarshal(target *Target) ([]byte, error) {
	outMap := make(map[uint32]struct {
		Count        uint32
		HitCalls     []string
		FirstHitTime time.Duration
		Progs        []string
	}, len(hitLog))
	for key, val := range hitLog {
		hitCalls := make([]string, 0, len(val.HitCalls))
		for _, callid := range val.HitCalls {
			callName := "extra"
			if callid > 0 && callid < len(target.Syscalls) {
				callName = target.Syscalls[callid].Name
			}
			hitCalls = append(hitCalls, callName)
		}
		outMap[key] = struct {
			Count        uint32
			HitCalls     []string
			FirstHitTime time.Duration
			Progs        []string
		}{
			Count:        val.Count,
			Progs:        val.Progs,
			HitCalls:     hitCalls,
			FirstHitTime: val.FirstHitTime,
		}
	}
	return json.Marshal(outMap)
}

type CallMapItem struct {
	Module      string
	FullVersion []string
	SimpVersion []string
	TrimVersion []string
}

func IsFileGenCallName(name string) bool {
	return strings.HasPrefix(name, "mk") || strings.HasPrefix(name, "open") || name == "creat" ||
		(strings.Contains(name, "mount") && !strings.Contains(name, "umount") && name != "move_mount")
}

func (target *Target) GenCallRelationData() (map[int][]int, map[int][]int) {
	// full version
	// fullCallCtorMap := target.GenTarget2Relate()
	// fullCallUserMap := target.GenRelate2Context()

	// only consider simplest input and output resource
	call2OutRescs := make([][]*ResourceDesc, len(target.Syscalls))
	inpResc2Calls := make(map[*ResourceDesc][]int, len(target.Resources))
	fileGenCalls := make(map[int]bool, 0)
	fileUseCalls := make([]int, 0)

	resc2FullUsers := make(map[*ResourceDesc][]int, len(target.Resources))
	resc2MatchUsers := make(map[*ResourceDesc][]int, len(target.Resources))

	callFullUserMap := make(map[int][]int, len(target.Syscalls))
	callMatchUserMap := make(map[int][]int, len(target.Syscalls))
	callCtorMap := make(map[int][]int, len(target.Syscalls))

	for metaId, meta := range target.Syscalls {
		inpRescs, outRescs, hasFileInput := getSimpleResources(meta)
		if len(outRescs) > 0 {
			call2OutRescs[metaId] = outRescs
		}
		if meta.Name == "sendfile64" {
			fmt.Printf("break here")
		}
		if hasFileInput {
			if IsFileGenCallName(meta.Name) {
				fileGenCalls[metaId] = true
			} else {
				fileUseCalls = append(fileUseCalls, metaId)
			}
		}
		for _, inpResc := range inpRescs {
			inpResc2Calls[inpResc] = append(inpResc2Calls[inpResc], metaId)
		}
	}

	// for call := range fileGenCalls {
	// 	fmt.Printf("file gen call: %v\n", target.Syscalls[call].Name)
	// }
	// for _, call := range fileUseCalls {
	// 	fmt.Printf("file use call: %v\n", target.Syscalls[call].Name)
	// }

	matchStat := 0
	unmatchStat := 0
	for _, res := range target.Resources {
		userMap := make(map[int]int)
		matchUserNum := 0
		for inpResc, calls := range inpResc2Calls {
			if isCompatibleResourceImpl(inpResc.Kind, res.Kind, true) {
				level := 1
				if len(inpResc.Kind) == len(res.Kind) {
					level = 2
					matchUserNum += len(calls)
				}
				for _, call := range calls {
					userMap[call] = level
				}

			}
		}
		if len(userMap) > 0 {
			fullUsers := make([]int, 0, len(userMap))
			var matchUsers []int
			if matchUserNum > 0 {
				matchUsers = make([]int, 0, matchUserNum)
			}
			for call, level := range userMap {
				fullUsers = append(fullUsers, call)
				if level == 2 {
					matchUsers = append(matchUsers, call)
				}
			}
			if matchUserNum == 0 {
				matchUsers = fullUsers
				unmatchStat += 1
				// fmt.Printf("unmatch resc: %v\n", res.Kind)
			} else {
				matchStat += 1
			}
			resc2FullUsers[res] = fullUsers
			resc2MatchUsers[res] = matchUsers
		}
	}

	// fmt.Printf("match: %v, unmatch: %v\n", matchStat, unmatchStat)

	for srcCallId, outRescs := range call2OutRescs {
		allUserMap := make(map[int]int)
		matchUserNum := 0
		if target.Syscalls[srcCallId].Name == "sendfile64" {
			fmt.Printf("break here")
		}

		for _, outResc := range outRescs {
			for _, call := range resc2FullUsers[outResc] {
				allUserMap[call] = 1
			}
			matchUsers := resc2MatchUsers[outResc]
			matchUserNum += len(matchUsers)
			for _, call := range matchUsers {
				allUserMap[call] = 2
			}
		}
		if fileGenCalls[srcCallId] {
			for _, call := range fileUseCalls {
				allUserMap[call] = 2
			}
		}

		if len(allUserMap) > 0 {
			allFullUsers := make([]int, 0, len(allUserMap))
			var allMatchUsers []int
			if matchUserNum > 0 {
				allMatchUsers = make([]int, 0, matchUserNum)
			}
			for call, level := range allUserMap {
				allFullUsers = append(allFullUsers, call)
				if level == 2 {
					allMatchUsers = append(allMatchUsers, call)
				}
			}
			if matchUserNum == 0 {
				allMatchUsers = allFullUsers
			}
			callFullUserMap[srcCallId] = allFullUsers
			callMatchUserMap[srcCallId] = allMatchUsers
		}
	}

	for srcCall, userCalls := range callFullUserMap {
		for _, user := range userCalls {
			callCtorMap[user] = append(callCtorMap[user], srcCall)
		}
	}

	limitCallUserMap := target.limitCallScope(callMatchUserMap)
	limitCallCtorMap := target.limitCallScope(callCtorMap)

	target.outCallMap(callCtorMap, limitCallCtorMap, "target2relate2.json")

	return limitCallCtorMap, limitCallUserMap
}

func (target *Target) limitCallScope(callMap map[int][]int) map[int][]int {
	litmitCallMap := make(map[int][]int, len(callMap))

	moduleParser := make(map[string][]string)
	getNameByLevel := func(module string, level int) string {
		seqs, ok := moduleParser[module]
		if !ok {
			seqs = make([]string, 0)
			curr := module
			for {
				seqs = append(seqs, module)
				idx := strings.LastIndex(curr, "_")
				if idx == -1 {
					break
				}
				curr = curr[:idx]
			}
			moduleParser[module] = seqs
		}
		if level >= len(seqs) {
			return ""
		} else {
			return seqs[level]
		}
	}

	for from, toCalls := range callMap {
		fromMeta := target.Syscalls[from]
		limitToCalls := make([]int, 0, len(toCalls)/2)
		// log.Printf("src module: %v", fromMeta.Module)
		maxIterCount := strings.Count(fromMeta.Module, "_") + 2
		for level := 0; level < maxIterCount; level++ {
			for _, toCall := range toCalls {
				superModule := getNameByLevel(fromMeta.Module, level)
				if superModule == "" {
					superModule = "sys"
				}
				if superModule == target.Syscalls[toCall].Module {
					limitToCalls = append(limitToCalls, toCall)
				}
				// } else {
				// 	log.Printf("un match module: %v", target.Syscalls[call].Module)
				// }
			}
			if len(limitToCalls) > 0 {
				break
			}
		}
		if len(limitToCalls) == 0 {
			limitToCalls = toCalls
		}
		litmitCallMap[from] = limitToCalls
		// else {
		// log.Printf("call %v, src module: %v, all related calls are banned", fromMeta.Name, fromMeta.Module)
		// }
	}
	return litmitCallMap
}

func (target *Target) outCallMap(simpCallMap, sameModuleMap map[int][]int, outFileName string) {
	allCallMap := make(map[string]CallMapItem, len(simpCallMap))

	// for check: require simpCallMap is subset of fullCallMap
	// for fromCall, toCalls := range simpCallMap {
	// 	if fullUserCalls, ok := fullCallMap[fromCall]; ok {
	// 		fullCallMap := make(map[int]bool)
	// 		for _, call := range fullUserCalls {
	// 			fullCallMap[call] = true
	// 		}
	// 		for _, call := range toCalls {
	// 			if !fullCallMap[call] {
	// 				log.Printf("%v: tcall:%v, rcall: %v", outFileName, fromCall, call)
	// 			}
	// 		}
	// 	} else {
	// 		log.Printf("%v: %v not in", outFileName, fromCall)
	// 	}
	// }
	// start to combine data
	callIds2Names := func(raws []int) []string {
		if len(raws) == 0 {
			return nil
		}
		sort.Ints(raws)
		res := make([]string, 0, len(raws))
		for _, raw := range raws {
			res = append(res, target.Syscalls[raw].Name)
		}
		return res
	}

	for fromCall := range simpCallMap {
		simpToCalls := callIds2Names(simpCallMap[fromCall])
		trimToCalls := callIds2Names(sameModuleMap[fromCall])
		allCallMap[target.Syscalls[fromCall].Name] = CallMapItem{
			Module:      target.Syscalls[fromCall].Module,
			SimpVersion: simpToCalls,
			TrimVersion: trimToCalls,
		}
	}

	data, err := json.MarshalIndent(allCallMap, "", "\t")
	if err != nil {
		log.Fatalf("marshal fail %v", err)
	}
	err = osutil.WriteFile(outFileName, data)
	if err != nil {
		log.Fatalf("write data fail %v", err)
	}
}

func getSimpleResources(c *Syscall) (inpRescs []*ResourceDesc, outRescs []*ResourceDesc, hasFileInput bool) {
	inpDedup := make(map[*ResourceDesc]bool)
	outDedup := make(map[*ResourceDesc]bool)
	ForeachCallType(c, func(typ Type, ctx *TypeCtx) {
		if typ.Optional() {
			ctx.Stop = true
			return
		}

		switch typ1 := typ.(type) {
		case *ResourceType:
			if ctx.Dir != DirOut && !inpDedup[typ1.Desc] {
				inpDedup[typ1.Desc] = true
				inpRescs = append(inpRescs, typ1.Desc)
			}
			if ctx.Dir != DirIn && !outDedup[typ1.Desc] {
				outDedup[typ1.Desc] = true
				outRescs = append(outRescs, typ1.Desc)
			}
		case *BufferType:
			if ctx.Dir != DirOut && typ1.Kind == BufferFilename {
				hasFileInput = true
			}

		case *StructType, *UnionType:
			ctx.Stop = true
		}
	})
	return
}

func (target *Target) GenTarget2Relate() map[int][]int {
	callRelationMap := make(map[int][]int, len(target.Syscalls))
	for metaId, meta := range target.Syscalls {
		rcallMap := make(map[int]bool)
		for _, res := range meta.inputResources {
			for _, ctor := range res.Ctors {
				if ctor.Precise {
					rcallMap[ctor.Call] = true
				}
			}
		}
		rcalls := make([]int, 0, len(rcallMap))
		for k := range rcallMap {
			rcalls = append(rcalls, k)
		}
		callRelationMap[metaId] = rcalls
	}
	return callRelationMap
}

func (target *Target) GenRelate2Context() map[int][]int {
	relContextMap := make(map[int][]int, len(target.Syscalls))
	for metaId, meta := range target.Syscalls {
		for _, res := range meta.inputResources {
			for _, ctor := range res.Ctors {
				if ctor.Precise {
					relContextMap[ctor.Call] = append(relContextMap[ctor.Call], metaId)
				}
			}
		}
	}
	return relContextMap
}
