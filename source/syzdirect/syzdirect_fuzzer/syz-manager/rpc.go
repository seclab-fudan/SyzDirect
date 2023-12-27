// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type RPCServer struct {
	mgr                   RPCManagerView
	cfg                   *mgrconfig.Config
	modules               []host.KernelModule
	port                  int
	targetEnabledSyscalls map[*prog.Syscall]bool
	coverFilter           map[uint32]uint32
	stats                 *Stats
	batchSize             int

	mu            sync.Mutex
	fuzzers       map[string]*Fuzzer
	checkResult   *rpctype.CheckArgs
	maxSignal     signal.Signal
	corpusSignal  signal.Signal
	corpusCover   cover.Cover
	rotator       *prog.Rotator
	rnd           *rand.Rand
	checkFailures int

	callPairMap    prog.CallPairMap
	directCalls    []int
	maxDistance    uint32
	minDistance    uint32
	hitLog         prog.GlobalHitLog
	hitMu          sync.Mutex
	lastHitLogTime time.Time
	callTimeMap    map[int]time.Time
	// rpcCallPairMap prog.RpcCallPairMap

	cpRecorder    prog.ManagerCallPairRecorder
	cpLogFp       *os.File
	detailCorpus  *os.File
	lastCPLogTime time.Time
}

type Fuzzer struct {
	name          string
	rotated       bool
	inputs        []rpctype.Input
	newMaxSignal  signal.Signal
	rotatedSignal signal.Signal
	machineInfo   []byte
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect([]host.KernelModule) (
		[]rpctype.Input, BugFrames, map[uint32]uint32, []byte, error)
	machineChecked(result *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool) map[int]map[int]bool
	newInput(inp rpctype.Input, sign signal.Signal) bool
	candidateBatch(size int) []rpctype.Candidate
	rotateCorpus() bool
	getFuzzingTime() time.Duration
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	cpLogFp, err := os.OpenFile(path.Join(mgr.cfg.Workdir, "cplog.txt"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("failed to open file %v", err)
	}
	detailCorpus, err := os.OpenFile(path.Join(mgr.cfg.Workdir, "detailCorpus.txt"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("failed to open file %v", err)
	}
	serv := &RPCServer{
		mgr:           mgr,
		cfg:           mgr.cfg,
		stats:         mgr.stats,
		fuzzers:       make(map[string]*Fuzzer),
		rnd:           rand.New(rand.NewSource(time.Now().UnixNano())),
		callPairMap:   mgr.callPairMap,
		minDistance:   prog.MaxDist,
		maxDistance:   0,
		hitLog:        make(prog.GlobalHitLog),
		callTimeMap:   make(map[int]time.Time),
		cpRecorder:    make(prog.ManagerCallPairRecorder),
		cpLogFp:       cpLogFp,
		detailCorpus:  detailCorpus,
		lastCPLogTime: time.Now(),
	}
	serv.batchSize = 5
	if serv.batchSize < mgr.cfg.Procs {
		serv.batchSize = mgr.cfg.Procs
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return nil, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	serv.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	return serv, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.stats.vmRestarts.inc()

	corpus, bugFrames, coverFilter, coverBitmap, err := serv.mgr.fuzzerConnect(a.Modules)
	if err != nil {
		return err
	}
	serv.coverFilter = coverFilter
	serv.modules = a.Modules

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := &Fuzzer{
		name:        a.Name,
		machineInfo: a.MachineInfo,
	}
	serv.fuzzers[a.Name] = f
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces
	r.CoverFilterBitmap = coverBitmap
	r.EnabledCalls = serv.cfg.Syscalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.cfg.Target.Revision
	r.RunTime = serv.mgr.getFuzzingTime()
	r.HitIndex = serv.cfg.HitIndex
	r.CallPairMap = serv.callPairMap
	r.RpcCallPairMap = serv.cpRecorder.ToRpcCallPair()

	if serv.mgr.rotateCorpus() && serv.rnd.Intn(5) == 0 {
		// We do rotation every other time because there are no objective
		// proofs regarding its efficiency either way.
		// Also, rotation gives significantly skewed syscall selection
		// (run prog.TestRotationCoverage), it may or may not be OK.
		r.CheckResult = serv.rotateCorpus(f, corpus)
	} else {
		r.CheckResult = serv.checkResult
		f.inputs = corpus
		f.newMaxSignal = serv.maxSignal.Copy()
	}
	return nil
}

func (serv *RPCServer) rotateCorpus(f *Fuzzer, corpus []rpctype.Input) *rpctype.CheckArgs {
	// Fuzzing tends to stuck in some local optimum and then it fails to cover
	// other state space points since code coverage is only a very approximate
	// measure of logic coverage. To overcome this we introduce some variation
	// into the process which should cause steady corpus rotation over time
	// (the same coverage is achieved in different ways).
	//
	// First, we select a subset of all syscalls for each VM run (result.EnabledCalls).
	// This serves 2 goals: (1) target fuzzer at a particular area of state space,
	// (2) disable syscalls that cause frequent crashes at least in some runs
	// to allow it to do actual fuzzing.
	//
	// Then, we remove programs that contain disabled syscalls from corpus
	// that will be sent to the VM (f.inputs). We also remove 10% of remaining
	// programs at random to allow to rediscover different variations of these programs.
	//
	// Then, we drop signal provided by the removed programs and also 10%
	// of the remaining signal at random (f.newMaxSignal). This again allows
	// rediscovery of this signal by different programs.
	//
	// Finally, we adjust criteria for accepting new programs from this VM (f.rotatedSignal).
	// This allows to accept rediscovered varied programs even if they don't
	// increase overall coverage. As the result we have multiple programs
	// providing the same duplicate coverage, these are removed during periodic
	// corpus minimization process. The minimization process is specifically
	// non-deterministic to allow the corpus rotation.
	//
	// Note: at no point we drop anything globally and permanently.
	// Everything we remove during this process is temporal and specific to a single VM.
	calls := serv.rotator.Select()

	var callIDs []int
	callNames := make(map[string]bool)

	for _, dcall := range serv.directCalls {
		calls[serv.cfg.Target.Syscalls[dcall]] = true
	}

	for call := range calls {
		callNames[call.Name] = true
		callIDs = append(callIDs, call.ID)
	}

	f.inputs, f.newMaxSignal = serv.selectInputs(callNames, corpus, serv.maxSignal)
	// Remove the corresponding signal from rotatedSignal which will
	// be used to accept new inputs from this manager.
	f.rotatedSignal = serv.corpusSignal.Intersection(f.newMaxSignal)
	f.rotated = true

	result := *serv.checkResult
	result.EnabledCalls = map[string][]int{serv.cfg.Sandbox: callIDs}
	return &result
}

func (serv *RPCServer) selectInputs(enabled map[string]bool, inputs0 []rpctype.Input, signal0 signal.Signal) (
	inputs []rpctype.Input, signal signal.Signal) {
	signal = signal0.Copy()
	for _, inp := range inputs0 {
		calls, _, err := prog.CallSet(inp.Prog)
		if err != nil {
			panic(fmt.Sprintf("rotateInputs: CallSet failed: %v\n%s", err, inp.Prog))
		}
		for call := range calls {
			if !enabled[call] {
				goto drop
			}
		}
		if serv.rnd.Float64() > 0.9 {
			goto drop
		}
		inputs = append(inputs, inp)
		continue
	drop:
		for _, sig := range inp.Signal.Elems {
			delete(signal, sig)
		}
	}
	signal.Split(len(signal) / 10)
	return inputs, signal
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *map[int]map[int]bool) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkResult != nil {
		return nil // another VM has already made the check
	}
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	if len(serv.cfg.EnabledSyscalls) != 0 && len(a.DisabledCalls[serv.cfg.Sandbox]) != 0 {
		disabled := make(map[string]string)
		for _, dc := range a.DisabledCalls[serv.cfg.Sandbox] {
			disabled[serv.cfg.Target.Syscalls[dc.ID].Name] = dc.Reason
		}
		for _, id := range serv.cfg.Syscalls {
			name := serv.cfg.Target.Syscalls[id].Name
			if reason := disabled[name]; reason != "" {
				log.Logf(0, "disabling %v: %v", name, reason)
			}
		}
	}
	if a.Error != "" {
		log.Logf(0, "machine check failed: %v", a.Error)
		serv.checkFailures++
		if serv.checkFailures == 10 {
			log.Fatalf("machine check failing")
		}
		return fmt.Errorf("machine check failed: %v", a.Error)
	}
	serv.targetEnabledSyscalls = make(map[*prog.Syscall]bool)
	for _, call := range a.EnabledCalls[serv.cfg.Sandbox] {
		serv.targetEnabledSyscalls[serv.cfg.Target.Syscalls[call]] = true
	}
	if len(serv.callPairMap) > 0 {
		allCallMap := make(map[int]bool)
		for tcall, rcalls := range serv.callPairMap {
			meta := serv.cfg.Target.Syscalls[tcall]
			if !serv.targetEnabledSyscalls[meta] {
				log.Logf(0, "[syzgo]: target call %v %v disable", tcall, meta.Name)
				delete(serv.callPairMap, tcall)
				continue
			}
			allCallMap[tcall] = true
			newRCalls := make([]int, 0, len(rcalls))
			for _, rcall := range rcalls {
				rcallMeta := serv.cfg.Target.Syscalls[rcall]
				if !serv.targetEnabledSyscalls[rcallMeta] {
					log.Logf(0, "[syzgo]: relate call %v %v (of %v) disable:", rcall, rcallMeta.Name, meta.Name)
				} else {
					newRCalls = append(newRCalls, rcall)
					allCallMap[rcall] = true
				}
			}
			serv.callPairMap[tcall] = newRCalls
		}
		if len(serv.callPairMap) == 0 {
			log.Fatalf("all target calls are disabled")
		}
		keys := make([]int, 0, len(allCallMap))
		for k := range allCallMap {
			keys = append(keys, k)
		}
		serv.directCalls = keys
	} else {
		log.Logf(0, "[syzgo]: fuzzing in none target syscall mode")
	}

	log.Logf(0, "machine check:")
	log.Logf(0, "%-24v: %v/%v", "syscalls", len(serv.targetEnabledSyscalls), len(serv.cfg.Target.Syscalls))
	for _, feat := range a.Features.Supported() {
		log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
	}
	includedCalls := serv.mgr.machineChecked(a, serv.targetEnabledSyscalls)
	a.DisabledCalls = nil
	serv.checkResult = a
	serv.rotator = prog.MakeRotator(serv.cfg.Target, serv.targetEnabledSyscalls, serv.rnd)
	*r = includedCalls
	return nil
}

func (serv *RPCServer) NewInput(a *rpctype.NewInputArgs, r *int) error {
	inputSignal := a.Signal.Deserialize()
	log.Logf(4, "new input from %v for syscall %v (signal=%v, cover=%v)",
		a.Name, a.Call, inputSignal.Len(), len(a.Cover))
	bad, disabled := checkProgram(serv.cfg.Target, serv.targetEnabledSyscalls, a.Input.Prog)
	if bad || disabled {
		log.Logf(0, "rejecting program from fuzzer (bad=%v, disabled=%v):\n%s", bad, disabled, a.Input.Prog)
		return nil
	}
	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	// Note: f may be nil if we called shutdownInstance,
	// but this request is already in-flight.
	genuine := !serv.corpusSignal.Diff(inputSignal).Empty()
	rotated := false
	if !genuine && f != nil && f.rotated {
		rotated = !f.rotatedSignal.Diff(inputSignal).Empty()
	}
	if !genuine && !rotated {
		return nil
	}
	if !serv.mgr.newInput(a.Input, inputSignal) {
		return nil
	}

	if f != nil && f.rotated {
		f.rotatedSignal.Merge(inputSignal)
	}
	diff := serv.corpusCover.MergeDiff(a.Cover)
	serv.stats.corpusCover.set(len(serv.corpusCover))
	if len(diff) != 0 && serv.coverFilter != nil {
		// Note: ReportGenerator is already initialized if coverFilter is enabled.
		rg, err := getReportGenerator(serv.cfg, serv.modules)
		if err != nil {
			return err
		}
		filtered := 0
		for _, pc := range diff {
			if serv.coverFilter[uint32(rg.RestorePC(pc))] != 0 {
				filtered++
			}
		}
		serv.stats.corpusCoverFiltered.add(filtered)
	}
	serv.stats.newInputs.inc()
	if rotated {
		serv.stats.rotatedInputs.inc()
	}
	logStruct := struct {
		Uptime string
		Prog   string
		Dist   uint32
	}{
		Uptime: serv.mgr.getFuzzingTime().String(),
		Prog:   string(a.Prog),
		Dist:   a.Dist,
	}
	data, err := json.MarshalIndent(logStruct, "", "\t")
	if err != nil {
		log.Fatalf("marshal err %v\n", err)
	}
	_, err = serv.detailCorpus.Write(append(data, '\n'))
	if err != nil {
		log.Fatalf("write err %v\n", err)
	}

	if len(a.ProgHitCounts) > 0 {
		rawProg := string(a.Prog)
		serv.hitMu.Lock()
		for hitIdx, progHitItem := range a.ProgHitCounts {
			item := serv.hitLog[hitIdx]
			if item.FirstHitTime == 0 {
				item.FirstHitTime = serv.mgr.getFuzzingTime()
			}
			if len(item.Progs) < 10 {
				item.AddCallIds(progHitItem.CallIds)
				item.Progs = append(item.Progs, rawProg)
			}
			serv.hitLog[hitIdx] = item
		}
		serv.hitMu.Unlock()
	}
	if a.Dist != prog.InvalidDist && a.TcallId != -1 {
		serv.cpRecorder.HandlerProgDist(a.Prog, a.Dist, a.TcallId, a.RcallId)
		if time.Since(serv.lastCPLogTime) > 2*time.Minute {
			data := serv.cpRecorder.CustomMarshal(serv.cfg.Target, serv.mgr.getFuzzingTime())
			_, err := serv.cpLogFp.Write(append(data, '\n'))
			if err != nil {
				log.Fatalf("failed to write data %v", err)
			}
			serv.lastCPLogTime = time.Now()
		}
	}

	if a.Dist != prog.InvalidDist && a.Dist > serv.maxDistance {
		serv.maxDistance = a.Dist
		serv.stats.maxDistance.set(int(a.Dist))
	}
	if a.Dist < serv.minDistance {
		if !genuine {
			log.Logf(0, "catch prog dist %v (lower than %v), but not genuine", a.Dist, serv.minDistance)
		}
		serv.minDistance = a.Dist
		serv.stats.minDistance.set(int(a.Dist))
	}
	if genuine {
		serv.corpusSignal.Merge(inputSignal)
		serv.stats.corpusSignal.set(serv.corpusSignal.Len())

		a.Input.Cover = nil // Don't send coverage back to all fuzzers.
		a.Input.RawCover = nil
		a.Input.ProgHitCounts = nil
		for _, other := range serv.fuzzers {
			if other == f || other.rotated {
				continue
			}
			other.inputs = append(other.inputs, a.Input)
		}
	}
	return nil
}

func (serv *RPCServer) LogHitCount(a *rpctype.HitCountArgs, r *int) error {
	serv.hitMu.Lock()
	defer serv.hitMu.Unlock()
	for hitIdx, newItem := range a.HitLog {
		oldItem, ok := serv.hitLog[hitIdx]
		if !ok {
			newItem.FirstHitTime = serv.mgr.getFuzzingTime()
			serv.hitLog[hitIdx] = newItem
			continue
		}
		oldItem.Count += newItem.Count
		if len(oldItem.Progs) < 10 {
			oldItem.AddCallIds(newItem.HitCalls)
			oldItem.Progs = append(oldItem.Progs, newItem.Progs...)
		}
		serv.hitLog[hitIdx] = oldItem
	}
	if newItem, ok := a.HitLog[serv.cfg.HitIndex]; ok {
		for _, call := range newItem.HitCalls {
			if _, ok = serv.callPairMap[call]; ok {
				if _, ok = serv.callTimeMap[call]; !ok {
					serv.callTimeMap[call] = time.Now()
				}
			}
		}
	}

	if time.Since(serv.lastHitLogTime) > 5*time.Minute {
		hitLogFile := filepath.Join(serv.cfg.Workdir, "hitLog.json")
		data, err := serv.hitLog.CustomMarshal(serv.cfg.Target)
		if err != nil {
			log.Fatalf("failed to marshal hit log %v", err)
		}
		err = os.WriteFile(hitLogFile, data, 0644)
		if err != nil {
			log.Fatalf("failed to write data to %v: %v", hitLogFile, err)
		}
		serv.lastHitLogTime = time.Now()
	}
	return nil
}

func (serv *RPCServer) Poll(a *rpctype.PollArgs, r *rpctype.PollRes) error {
	serv.stats.mergeNamed(a.Stats)

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		// This is possible if we called shutdownInstance,
		// but already have a pending request from this instance in-flight.
		log.Logf(1, "poll: fuzzer %v is not connected", a.Name)
		return nil
	}
	log.Logf(0, "[syzgo]: triage %v smash %v candidate %v", a.TriageQueueSize, a.SmashQueueSize, a.CandidateQueueSize)
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		serv.stats.maxSignal.set(len(serv.maxSignal))
		for _, f1 := range serv.fuzzers {
			if f1 == f || f1.rotated {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	if f.rotated {
		// Let rotated VMs run in isolation, don't send them anything.
		return nil
	}
	r.MaxSignal = f.newMaxSignal.Split(2000).Serialize()
	if a.NeedCandidates {
		r.Candidates = serv.mgr.candidateBatch(serv.batchSize)
	}
	if len(r.Candidates) == 0 {
		batchSize := serv.batchSize
		// When the fuzzer starts, it pumps the whole corpus.
		// If we do it using the final batchSize, it can be very slow
		// (batch of size 6 can take more than 10 mins for 50K corpus and slow kernel).
		// So use a larger batch initially (we use no stats as approximation of initial pump).
		const initialBatch = 50
		if len(a.Stats) == 0 && batchSize < initialBatch {
			batchSize = initialBatch
		}
		for i := 0; i < batchSize && len(f.inputs) > 0; i++ {
			last := len(f.inputs) - 1
			r.NewInputs = append(r.NewInputs, f.inputs[last])
			f.inputs[last] = rpctype.Input{}
			f.inputs = f.inputs[:last]
		}
		if len(f.inputs) == 0 {
			f.inputs = nil
		}
	}
	log.Logf(4, "poll from %v: candidates=%v inputs=%v maxsignal=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.MaxSignal.Elems))
	return nil
}

func (serv *RPCServer) shutdownInstance(name string) []byte {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	fuzzer := serv.fuzzers[name]
	if fuzzer == nil {
		return nil
	}
	delete(serv.fuzzers, name)
	return fuzzer.machineInfo
}
