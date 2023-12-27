// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
		ProgExtra: ProgExtra{
			Dist: InvalidDist,
		},
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}

func (target *Target) GenerateInGo(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	if !ct.GoEnable {
		return target.Generate(rs, ncalls, ct)
	}
	tcallId, rcallId := ct.SelectCallPair(rand.New(rs))
	// log.Printf("tcall id: %v, rcall id: %v\n", tcallId, rcallId)
	return target.generateHelper(ct, rs, ncalls, tcallId, rcallId)
}

func (target *Target) MultiGenerateInGo(rs rand.Source, ct *ChoiceTable, includedCalls map[int]map[int]bool) []*Prog {
	progs := make([]*Prog, 0, len(ct.callPairInfos)*CallPairInitNum)
	for i := 0; i < CallPairInitNum; i++ {
		for j := 0; j < len(ct.callPairInfos); j++ {
			inf := &ct.callPairInfos[j]
			if len(ct.infoIdxMap[inf.Tcall]) > 1 && inf.Rcall == -1 {
				continue
			}
			if rcallMap, ok := includedCalls[inf.Tcall]; ok && (inf.Rcall == -1 || rcallMap[inf.Rcall]) {
				continue
			}
			ncalls := 2
			if inf.Rcall == -1 {
				ncalls = 1
			}
			progs = append(progs, target.generateHelper(ct, rs, ncalls, inf.Tcall, inf.Rcall))
		}
	}
	return progs
}

func (p *Prog) HasTcall(ct *ChoiceTable) bool {
	if p.Tcall != nil {
		return true
	}
	for i := len(p.Calls) - 1; i >= 0; i-- {
		if rcallMap, ok := ct.infoIdxMap[p.Calls[i].Meta.ID]; ok {
			p.Tcall = p.Calls[i]
			p.Rcall = nil
			for j := 0; j < i; j++ {
				if _, ok = rcallMap[p.Calls[j].Meta.ID]; ok {
					p.Rcall = p.Calls[j]
					break
				}
			}
			return true
		}
	}
	return false
}

func (target *Target) generateHelper(ct *ChoiceTable, rs rand.Source, ncalls, tcallId, rcallId int) *Prog {
	var rcall *Call
	s := newState(target, ct, nil)
	r := newRand(target, rs)
	p := &Prog{
		Target: target,
		ProgExtra: ProgExtra{
			Dist: InvalidDist,
		},
	}

	if rcallId != -1 {
		rcalls := r.generateParticularCall(s, target.Syscalls[rcallId])
		for _, c := range rcalls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
		rcall = rcalls[len(rcalls)-1]
	}

	for len(p.Calls) < ncalls-1 {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}

	r.rcall = rcall
	targetCalls := r.generateParticularCall(s, r.target.Syscalls[tcallId])
	p.Rcall = rcall
	p.Tcall = targetCalls[len(targetCalls)-1]

	rmIdx := len(p.Calls) - 1
	if rmIdx < 0 {
		rmIdx = 0
	}
	p.Calls = append(p.Calls, targetCalls...)
	for len(p.Calls) > ncalls {
		isSucc := p.RemoveCall(rmIdx)
		if !isSucc && rmIdx == 0 {
			rmIdx = 1
		} else if rmIdx > 0 {
			rmIdx--
		}
	}
	return p
}

func (target *Target) FixExtraCalls(p *Prog, rs rand.Source, ct *ChoiceTable, ncalls int, c *Call) {
	if p.Tcall != nil {
		return
	}
	s := analyze(ct, nil, p, nil)
	r := newRand(target, rs)

	tcallId, rcallId := ct.SelectCallPair(r.Rand)
	// mini流程里删掉tcall时会顺带将rcall 清空，因此这里的判断应该是没有意义的
	if p.Rcall != nil {
		if _, ok := ct.infoIdxMap[tcallId][p.Rcall.Meta.ID]; !ok {
			p.Rcall = nil
		}
	}
	if rcallId == -1 {
		p.Rcall = nil
	}
	if p.Rcall == nil && rcallId != -1 {
		rcalls := r.generateParticularCall(s, target.Syscalls[rcallId])
		for _, c := range rcalls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
		p.Rcall = rcalls[len(rcalls)-1]
	}
	targetCalls := r.generateParticularCall(s, r.target.Syscalls[tcallId])
	p.Tcall = targetCalls[len(targetCalls)-1]
	rmIdx := len(p.Calls) - 1
	if rmIdx < 0 {
		rmIdx = 0
	}
	p.Calls = append(p.Calls, targetCalls...)
	for len(p.Calls) > ncalls {
		isSucc := false
		if p.Calls[rmIdx] != c {
			isSucc = p.RemoveCall(rmIdx)
		}
		if !isSucc && rmIdx == 0 {
			rmIdx = 1
		} else if rmIdx > 0 {
			rmIdx--
		}
	}
}
