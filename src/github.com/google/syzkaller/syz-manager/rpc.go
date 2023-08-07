// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"io"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/evtrack"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/ivshmem"
)

type RPCServer struct {
	mgr                   RPCManagerView
	cfg                   *mgrconfig.Config
	unpackedCfg           map[string]string
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
	vanilla       bool

	groupMu       sync.Mutex
	groupMin      chan int
	mergedGroups  []*prog.Group
	newGroups     []*prog.Group
	maxGroupID    uint64
	strategies    []prog.Strategy
	llvmLookup    *evtrack.LLVMLookup

	addrMu       sync.Mutex
	addrIn       io.WriteCloser
	addrOut      io.ReadCloser
	cacheMu      sync.Mutex
	subsysCache  map[uint32]string
	apiCache     map[uint32]bool
	subsysProbs  map[string]float64
	subsysStats  map[string]uint64
	groupsDropp  uint64
	groupsKept   uint64
	cacheMisses  uint64
	cacheHit     uint64

	statsMu           sync.Mutex
	shared_objects    uint64
	shared_accesses   uint64
	shared_acc_subsys map[string]uint64
	single_acc        uint64
}

type Fuzzer struct {
	name          string
	rotated       bool
	inputs        []rpctype.Input
	newMaxSignal  signal.Signal
	rotatedSignal signal.Signal
	machineInfo   []byte
	groups        map[uint64]*prog.Group
	used          map[uint64]bool
	changes       map[uint64]prog.Result
	inactive      map[uint64]bool
	ivshmem       []byte
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect([]host.KernelModule) (
		[]rpctype.Input, BugFrames, map[uint32]uint32, []byte, error)
	machineChecked(result *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool)
	newInput(inp rpctype.Input, sign signal.Signal) bool
	candidateBatch(size int) []rpctype.Candidate
	rotateCorpus() bool
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	serv := &RPCServer{
		mgr:         mgr,
		cfg:         mgr.cfg,
		unpackedCfg: mgr.loadCfg(),
		stats:       mgr.stats,
		fuzzers:     make(map[string]*Fuzzer),
		rnd:         rand.New(rand.NewSource(time.Now().UnixNano())),
		groupMin:    make(chan int, 1),
		vanilla:     mgr.cfg.Vanilla,
	}
	mgr.rpcserv = serv
	serv.initEvtrack(mgr.crashdir, serv.unpackedCfg["workdir"])

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

	// check whether fuzzer with this name exists already, then unmap sharedmem
	old := serv.fuzzers[a.Name]
	if old != nil {
		err := ivshmem.UnmapHostIvshmem(old.ivshmem)
		if err != nil {
			log.Fatalf("Unmap failed: %v", err)
		}
		delete(serv.fuzzers, a.Name)
		old.changes = nil
		old.groups =  nil
	}

	f := &Fuzzer{
		name:        a.Name,
		machineInfo: a.MachineInfo,
		groups:      make(map[uint64]*prog.Group),
		changes:     make(map[uint64]prog.Result),
		used:        make(map[uint64]bool),
		inactive:   make(map[uint64]bool),
	}

	f.ivshmem, err = ivshmem.GetSharedMappingHost(fmt.Sprintf("/dev/shm/ivshmemfile%s", a.Name))
	if err != nil {
		fmt.Println(err)
		panic("mmap failed")
	}

	serv.fuzzers[a.Name] = f
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces
	r.CoverFilterBitmap = coverBitmap
	r.EnabledCalls = serv.cfg.Syscalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.cfg.Target.Revision
	if !serv.vanilla {
		// choose x groups for fuzzer
		serv.groupMu.Lock()
		if len(serv.mergedGroups) > 0 {
			if len(serv.mergedGroups) < prog.GROUPS_PER_VM {
				for i := 0; i < len(serv.mergedGroups); i++ {
					grp := serv.mergedGroups[i]
					f.groups[grp.ID] = grp
					f.changes[grp.ID] = prog.Result{Res: grp, Changed: true}
				}
			} else {
				min := 0
				max := len(serv.mergedGroups)
				rnds := serv.rnd.Perm(max)
				for i := 0; i < prog.GROUPS_PER_VM; i++ {
					ind := min + rnds[i]
					grp := serv.mergedGroups[ind]
					if _, present := f.groups[grp.ID]; !present {
						f.groups[grp.ID] = grp
						f.changes[grp.ID] = prog.Result{Res: grp, Changed: true}
					}
				}
			}
		}
		serv.groupMu.Unlock()

		log.Logf(0, "Added %v groups to %v's changed list", len(f.groups), f.name)
	}
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

func (f *Fuzzer) assignAdditionalGroups(serv *RPCServer) {
	// choose x groups for fuzzer
	serv.groupMu.Lock()
	min := 0
	max := len(serv.mergedGroups)
	rnds := serv.rnd.Perm(max)
	for i := 0; i < max && len(f.groups) < max && len(f.groups) < prog.GROUPS_PER_VM; i++ {
		ind := min + rnds[i]
		grp := serv.mergedGroups[ind]
		_, present := f.groups[grp.ID]
		_, inactive := f.inactive[grp.ID]
		if !present && !inactive {
			f.groups[grp.ID] = grp
			f.changes[grp.ID] = prog.Result{Res: grp, Changed: true}
		}
	}
	serv.groupMu.Unlock()
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

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
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
	log.Logf(0, "machine check:")
	log.Logf(0, "%-24v: %v/%v", "syscalls", len(serv.targetEnabledSyscalls), len(serv.cfg.Target.Syscalls))
	for _, feat := range a.Features.Supported() {
		log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
	}
	serv.mgr.machineChecked(a, serv.targetEnabledSyscalls)
	a.DisabledCalls = nil
	serv.checkResult = a
	serv.rotator = prog.MakeRotator(serv.cfg.Target, serv.targetEnabledSyscalls, serv.rnd)
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

	if genuine {
		serv.corpusSignal.Merge(inputSignal)
		serv.stats.corpusSignal.set(serv.corpusSignal.Len())

		a.Input.Cover = nil // Don't send coverage back to all fuzzers.
		a.Input.RawCover = nil
		for _, other := range serv.fuzzers {
			if other == f || other.rotated {
				continue
			}
			other.inputs = append(other.inputs, a.Input)
		}
	}
	return nil
}

func readU64(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}

func writeU64(data []byte, num uint64) {
	binary.LittleEndian.PutUint64(data, num)
}

func (serv *RPCServer) GetStrategies(a *rpctype.GetStratArg, r *rpctype.GetStratRes) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		log.Fatalf("fuzzer %v is not connected", a.Name)
	}

	writeU64(f.ivshmem, uint64(0))
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(serv.strategies)
	if err != nil {
		log.Fatalf("Encoding of strategies failed: %v", err)
	}
	n := buf.Len()
	if n != copy(f.ivshmem[8:], buf.Bytes()) {
		r.Len = 0
		log.Fatalf("buffer was too small for strategies")
	}
	r.Len = uint64(n)

	return nil
}

func (serv *RPCServer) PollNew(a *rpctype.PollArgsNew, r *rpctype.PollResNew) error {
	serv.stats.mergeNamed(a.Stats)

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		log.Fatalf("fuzzer %v is not connected", a.Name)
	}
	serv.statsMu.Lock()
	for id := range a.NewUsed {
		f.used[id] = true
	}
	serv.statsMu.Unlock()
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		// read data from ivshmem
		for readU64(f.ivshmem) != 1 {}
		if a.EvtLen != 0 {
			batch := evtrack.DecodeBatchPb(f.ivshmem[8:(8+a.EvtLen)])
			go serv.add_groups(batch.Events)
		}

		for _, f1 := range serv.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	// some groups have syscalls that cannot be used by the VM
	toBeDeleted := make([]uint64, 0)
	for _, id := range a.DeletedIDs {
		delete(f.groups, id)
		ch, present := f.changes[id]
		if present {
			toBeDeleted = append(toBeDeleted, ch.Deleted...)
			delete(f.changes, id)
		}
		f.inactive[id] = true
	}
	// if fuzzer does not yet have x groups, assign additional groups
	if len(f.groups) < prog.GROUPS_PER_VM {
		f.assignAdditionalGroups(serv)
	}

	if len(toBeDeleted) > 0 {
		// this means we deleted at least 1 group, therefore we need to add a new one
		if len(f.changes) == 0 {
			panic("need to delete this stuff but cannot")
		}
		for id := range f.changes {
			ch := f.changes[id]
			ch.Deleted = append(ch.Deleted, toBeDeleted...)
			f.changes[id] = ch
			break
		}
	}
	// write data to ivshmem
	changes := make([]prog.Result, 0)
	ind := 0
	for _, res := range f.changes {
		if ind == 50 {
			break
		}
		changes = append(changes, res)
		ind++
	}
	for _, res := range changes {
		delete(f.changes, res.Res.ID)
	}

	writeU64(f.ivshmem, uint64(0))
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(changes)
	if err != nil {
		log.Fatalf("Encoding of groups failed: %v", err)
	}
	n := buf.Len()
	if n != copy(f.ivshmem[8:], buf.Bytes()) {
		r.ChangeLen = 0
		log.Fatalf("buffer was too small for changed")
	}
	r.ChangeLen = uint64(n)

	writeU64(f.ivshmem[8+n:], uint64(0))

	r.MaxSignal = f.newMaxSignal.Split(500).Serialize()
	if a.NeedCandidates {
		r.Candidates = serv.mgr.candidateBatch(serv.batchSize)
	}
	if len(r.Candidates) == 0 {
		batchSize := serv.batchSize
		// When the fuzzer starts, it pumps the whole corpus.
		// If we do it using the final batchSize, it can be very slow
		// (batch of size 6 can take more than 10 mins for 50K corpus and slow kernel).
		// So use a larger batch initially (we use no stats as approximation of initial pump).
		const initialBatch = 30
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
	log.Logf(4, "poll from %v: candidates=%v inputs=%v maxsignal=%v maxgroups=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.MaxSignal.Elems), len(changes))
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
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		serv.add_groups(a.MaxEvents)
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
	log.Logf(4, "poll from %v: candidates=%v inputs=%v maxsignal=%v maxgroups=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.MaxSignal.Elems), len(r.ChangedGroups))
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
