// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type InputTest struct {
	p    *prog.Prog
	sign signal.Signal
	sig  hash.Sig
}

func TestChooseProgram(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}

	const (
		maxIters   = 1000
		sizeCorpus = 1000
		eps        = 0.01
	)

	priorities := make(map[*prog.Prog]int64)
	for i, j := 0, 0; i < sizeCorpus; {
		dist := 200 * j
		j++
		for num := 0; num < j*2; num++ {
			i += 1
			inp := generateInput(target, rs, 10, 1, dist)
			fuzzer.addInputToCorpus(inp.p, inp.sign, inp.sig)
			prio := int64(1)
			if inp.p.Dist < 3450 { // dist > 3450 的值等于1，就没必要算
				prio = int64(100 * math.Exp(float64(inp.p.Dist)*-0.003))
				if prio < 1 {
					prio = 1
				}
			}
			priorities[inp.p] = prio
		}

	}
	snapshot := fuzzer.snapshot()
	counters := make(map[*prog.Prog]int)
	for it := 0; it < maxIters; it++ {
		counters[snapshot.chooseProgram(r, nil)]++
	}
	for p, prio := range priorities {
		// fmt.Printf("dist: %v, prio: %v\n", p.Dist, prio)
		prob := float64(prio) / float64(fuzzer.sumPrios)
		diff := math.Abs(prob*maxIters - float64(counters[p]))
		if diff > eps*maxIters {
			fmt.Printf("\tthe difference (%f) is higher than %f%%\n", diff, eps*100)
		}
	}
	stats := make(map[int]int)
	stats2 := make(map[int]int)
	for p := range priorities {
		stats[int(p.Dist)] += counters[p]
		stats2[int(p.Dist)] += 1
	}
	for k, v := range stats {
		fmt.Printf("dist: %v, prog num: %v, counter: %v\n", k, stats2[k], v)
	}
}

func TestAddInputConcurrency(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}

	const (
		routines = 10
		iters    = 100
	)

	for i := 0; i < routines; i++ {
		go func() {
			rs := rand.NewSource(0)
			r := rand.New(rs)
			for it := 0; it < iters; it++ {
				inp := generateInput(target, rs, 10, it, 0)
				fuzzer.addInputToCorpus(inp.p, inp.sign, inp.sig)
				snapshot := fuzzer.snapshot()
				snapshot.chooseProgram(r, nil).Clone()
			}
		}()
	}
}

func TestQueue(t *testing.T) {
	wq := newWorkQueue(10, nil)
	rs := rand.NewSource(0)
	// r := rand.New(rs)
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	for i := 0; i < 100; i++ {
		dist := (99 - i) * 10
		inp := generateInput(target, rs, 10, 1, dist)
		wq.enqueue(&WorkTriage{
			p: inp.p,
			info: ipc.CallInfo{
				Dist: inp.p.Dist,
			},
		})
	}
	for i := 0; i < 100; i++ {
		item := wq.dequeue()
		it := item.(*WorkTriage)
		log.Printf("dist: %v", it.p.Dist)
	}
}

func generateInput(target *prog.Target, rs rand.Source, ncalls, sizeSig int, dist int) (inp InputTest) {
	inp.p = target.Generate(rs, ncalls, target.DefaultChoiceTable())
	var raw []uint32
	for i := 1; i <= sizeSig; i++ {
		raw = append(raw, uint32(i))
	}
	inp.sign = signal.FromRaw(raw, 0)
	inp.p.Dist = uint32(dist)
	inp.sig = hash.Hash(inp.p.Serialize())
	return
}

func getTarget(t *testing.T, os, arch string) *prog.Target {
	t.Parallel()
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}
