package main

import (
	"io"
	"os"

	"bytes"
	"encoding/gob"
	"errors"
	"io/ioutil"
	"math/rand"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/evtrack"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type SortableEvents []prog.EvtrackEvent

func (l SortableEvents) Len() int {
	return len(l)
}

func (l SortableEvents) Less(i, j int) bool {
	return l[i].Ptr < l[j].Ptr || (l[i].Ptr == l[j].Ptr && l[i].EventType < l[j].EventType)
}

func (l SortableEvents) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

/*
 * Setup fields fo the rpcserver related to evtrack
 * event handling.
 *
 * The function loads caches, initializes the group
 * statistics, and probabilites.
 */
func (serv *RPCServer) initEvtrack(crashdir, workdir string) {
	subs := []string{
		"arch", "block", "certs", "crypto", "drivers", "fs", "ipc", "lib",
		"kernel", "mm", "net", "security", "sound",
	}
	serv.subsysProbs = make(map[string]float64)
	serv.subsysStats = make(map[string]uint64)
	for _, s := range subs {
		serv.subsysProbs[s] = float64(0.2)
		serv.subsysStats[s] = uint64(0)
	}

	// Stat collection
	serv.shared_acc_subsys = make(map[string]uint64)
	for _, s := range subs {
		serv.shared_acc_subsys[s] = uint64(0)
	}

	// load llvm info
	serv.llvmLookup = evtrack.LoadLLVMInfo(workdir + "/ptrs.txt")
	if serv.llvmLookup == nil {
		log.Logf(0, "No LLVM info available")
	} else {
		log.Logf(0, "LLVM info loaded")
	}

	// load evtrack_groups.dmp from disc
	log.Logf(0, "loading events...")
	eventDumpFile := workdir + "/evtrackgroups.dmp"
	serv.readEventsFromDumpFile(eventDumpFile)
	log.Logf(0, "loaded %d groups", len(serv.newGroups))

	// load caches from disc
	_, err := os.Stat(crashdir + "/cache.dmp")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Logf(0, "Cache file does not exist\n")
		} else {
			log.Logf(0, "Error opening cache file: %v\n", err)
		}
		serv.subsysCache = make(map[uint32]string)
	} else {
		content, err := ioutil.ReadFile(crashdir + "/cache.dmp")
		if err != nil {
			log.Logf(0, "Error while reading cache: %v\n", err)
			serv.subsysCache = make(map[uint32]string)
			return
		}
		dec := gob.NewDecoder(bytes.NewBuffer(content))
		err = dec.Decode(&serv.subsysCache)
		if err != nil {
			log.Logf(0, "Error while decoding cache: %v\n", err)
			serv.subsysCache = make(map[uint32]string)
		}
	}

	_, err = os.Stat(crashdir + "/api_cache.dmp")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Logf(0, "APICache file does not exist\n")
		} else {
			log.Logf(0, "Error opening api cache file: %v\n", err)
		}
		serv.apiCache = make(map[uint32]bool)
	} else {
		content, err := ioutil.ReadFile(crashdir + "/api_cache.dmp")
		if err != nil {
			log.Logf(0, "Error while reading api cache: %v\n", err)
			serv.apiCache = make(map[uint32]bool)
			return
		}
		dec := gob.NewDecoder(bytes.NewBuffer(content))
		err = dec.Decode(&serv.apiCache)
		if err != nil {
			log.Logf(0, "Error while decoding api cache: %v\n", err)
			serv.apiCache = make(map[uint32]bool)
		}
	}
	log.Logf(0, "Loading done, Cache size: %v, API cache size: %v\n", len(serv.subsysCache), len(serv.apiCache))

	cmd := exec.Command("addr2line", "-e", serv.unpackedCfg["uncompressedKernel"], "--functions")
	serv.addrIn, err = cmd.StdinPipe()
	if err != nil {
		log.Logf(0, "Connecting to stdin of addr2line process failed: %v\n", err)
		os.Exit(1)
	}
	serv.addrOut, err = cmd.StdoutPipe()
	if err != nil {
		log.Logf(0, "Connecting to stdout of addr2line process failed: %v\n", err)
		os.Exit(1)
	}
	err = cmd.Start()
	if err != nil {
		log.Logf(0, "Starting addr2line process failed: %v\n", err)
		os.Exit(1)
	}

	// create dir for stats output
	stats_dir := filepath.Join(workdir, "stats")
	osutil.MkdirAll(stats_dir)
	go serv.output_stats(stats_dir)

	serv.loadStrategies(workdir)
}

func (serv *RPCServer) readEventsFromDumpFile(dumpFile string) {
	content, err := ioutil.ReadFile(dumpFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Logf(0, "event dump file does not exist\n")
			return
		} else {
			log.Fatalf("event dump file read error: %v", err)
		}
	}

	var groups []*prog.Group
	dec := gob.NewDecoder(bytes.NewBuffer(content))
	err = dec.Decode(&groups)
	if err != nil {
		log.Fatalf("event dump decode error: %v", err)
	}
	serv.newGroups = groups

	for _, group := range serv.newGroups {
		if group.ID >= serv.maxGroupID {
			atomic.StoreUint64(&serv.maxGroupID, group.ID + 1)
		}
	}
}


/*
 * Fileformat for strategies.txt:
 *  - Every line corresponds to one strategy
 *  - Two elements of a strategy are separated by '|'
 *  - The values of an element are separated by ','
 *
 * Example:
 *    alloc, 1 | dealloc, 2 | read, 3
 */
func (serv *RPCServer) loadStrategies(workdir string) {
	_, err := os.Stat(workdir + "/strategies.txt")
	serv.strategies = make([]prog.Strategy, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Logf(0, "Strategies file does not exist\n")
		} else {
			log.Logf(0, "Error opening strategies file: %v\n", err)
		}
		return
	}
	content, err := ioutil.ReadFile(workdir + "/strategies.txt")
	if err != nil {
		log.Logf(0, "Error while reading strategies: %v\n", err)
		return
	}

	tokenToInt := map[string]prog.EvtrackEventType{
		"alloc": prog.EvtrackEventType(0),
		"dealloc": prog.EvtrackEventType(1),
		"read": prog.EvtrackEventType(2),
		"write": prog.EvtrackEventType(3),
	}
	stratsString := strings.Split(string(content[:]), "\n")
	var ok bool
	for _, stratString := range stratsString {
		if len(stratString) == 0 {
			continue
		}
		elements := strings.Split(stratString, "|")
		strat := make(prog.Strategy, len(elements))
		for i, elem := range elements {
			vals := strings.Split(elem, ",")
			if len(vals) < 2 || len(vals) > 3 {
				log.Fatalf("Wrong number of values for element '%s': %v\n",
					elem, len(vals))
			}
			for i := range vals {
				vals[i] = strings.TrimSpace(vals[i])
			}

			strat[i].EventType, ok = tokenToInt[vals[0]]
			if !ok {
				log.Fatalf("Unknown event type: %v\n", vals[0])
			}

			strat[i].ID, err = strconv.ParseInt(vals[1], 10, 64)
			if err != nil {
				log.Fatalf("ID has to be an int: %v", err)
			}
			if len(vals) == 2 && strat[i].ID < 0 {
				log.Fatalf("Negative ID is only allowed for repeated elements!")
			}

			if len(vals) == 3 {
				strat[i].Repeat = vals[2]
				_, err = strconv.ParseInt(vals[2], 10, 64)
				if vals[2][0] != '*' && vals[2][0] != 'r' && err != nil {
					log.Fatalf("Invalid repeat value: %v\n", vals[2])
				}
			}
		}
		serv.strategies = append(serv.strategies, strat)
	}
}

type AccessStats struct {
	SharedObjs          uint64
	SharedAccs          uint64
	SharedSubs          map[string]uint64
}

// output stats every 10mins to the stats directory
func (serv *RPCServer) output_stats(stats_dir string) {
	index := 0
	for 1 < 2 {
		time.Sleep(time.Minute * 10)
		serv.statsMu.Lock()
		var accs_stat AccessStats
		accs_stat.SharedObjs = serv.shared_objects
		accs_stat.SharedAccs = serv.shared_accesses
		accs_stat.SharedSubs = serv.shared_acc_subsys
		f, err := os.Create(filepath.Join(stats_dir, "stats_" + strconv.Itoa(index)))
		if err != nil {
			log.Logf(0, "Dumping metric stats failed: %v", err)
			return
		}
		buf := new(bytes.Buffer)
		enc := gob.NewEncoder(buf)
		err = enc.Encode(accs_stat)
		if err != nil {
			log.Logf(0, "Encoding metric stats failed: %v", err)
			f.Close()
			return
		}
		f.Write(buf.Bytes())
		f.Close()
		serv.statsMu.Unlock()
	}
}

/*
 * Convert the events to groups and add them to the server state.
 *
 * If necessary, calls minimize to reduce the number of groups. This function
 * operates on the state of serv. It may not be called by a caller holding
 * the mutex serv.groupMu.
 */

func (serv *RPCServer) add_groups(evlist [][]prog.EvtrackEvent) {
	groups := serv.group_events(evlist)
	serv.groupMu.Lock()
	defer serv.groupMu.Unlock()
	serv.newGroups = append(serv.newGroups, groups...)

	if len(serv.newGroups) >= 2000 {
		go serv.minimize()
	}
}

/*
 * Minimize groups by merging related ones.
 * This method should be called whenever the number of groups of the server
 * increases over a certain threshold (e.g., 1000 groups).
 *
 * It updates serv with the results of the minimization.
 */
func (serv *RPCServer) minimize() {
	select {
	case serv.groupMin <- 1:
		serv.groupMu.Lock()
		not_merged := len(serv.newGroups)
		serv.groupMu.Unlock()

		numPerRound := 2000
		for float32(not_merged) > 0.8*float32(numPerRound) {
			space := numPerRound
			if space > not_merged {
				space = not_merged
			}
			tmp := make([]*prog.Group, space)
			serv.groupMu.Lock()
			copy(tmp, serv.newGroups) // the number of groups could increase in the meantime
			serv.newGroups = serv.newGroups[space:]
			tmp = append(tmp, serv.mergedGroups...)
			serv.groupMu.Unlock()

			newly_merged, mergedRes := serv.find_merging_groups(tmp, uint64(space))
			newly_merged = filter_groups(newly_merged)

			// update server state
			not_merged = serv.update(mergedRes, newly_merged, not_merged, space)
			mergedRes = nil
		}

		<-serv.groupMin
		return

	default:
		//somebody else is minimizing, so nothing to do
		return
	}
}

func (serv *RPCServer) update(mergedRes []prog.Result, newly_merged []*prog.Group, not_merged int, space int) int {
	serv.mu.Lock()
	if !serv.vanilla {
		for _, f := range serv.fuzzers {
			toDelete := make([]uint64,0)
			for _, result := range mergedRes {
				if !result.Changed {
					continue
				}
				_, ok := f.groups[result.Res.ID]
				if ok {
					prev, ok := f.changes[result.Res.ID]
					if ok {
						result.Deleted = append(result.Deleted, prev.Deleted...)
					}
					f.changes[result.Res.ID] = result
					f.groups[result.Res.ID] = result.Res
				}
				for _, del := range result.Deleted {
					_, ok = f.groups[del]
					if ok {
						f.groups[result.Res.ID] = result.Res
						toDelete = append(toDelete, del)
						// changes to the now deleted group need to be propagated
						prev, ok := f.changes[del]
						if ok {
							result.Deleted = append(result.Deleted, prev.Deleted...)
							delete(f.changes, del)
						}
						// this record could exist already
						prev, ok = f.changes[result.Res.ID]
						if ok {
							result.Deleted = append(result.Deleted, prev.Deleted...)
						}
						f.changes[result.Res.ID] = result
					}
				}
			}
			for _, id := range toDelete {
				delete(f.groups, id)
			}
		}
	}
	serv.mu.Unlock()

	serv.groupMu.Lock()
	defer serv.groupMu.Unlock()
	serv.mergedGroups = newly_merged

	// update our state for the next round
	return len(serv.newGroups)
}

func (serv *RPCServer) group_events(evlist [][]prog.EvtrackEvent) []*prog.Group {
	/*
	 * Algorithm:
	 *  - sort array (for each process)
	 *  - just go over array once and group as long as the elements are within the
	 *    range of the first one
	 *   -> this requires that the allocation stays as the first element of the
	 *      group (-> stable sorting algorithm needed)
	 */
	dropped := uint64(0)
	kept := uint64(0)
	res := make([]*prog.Group, 0)
	for _, list := range evlist {
		// sort array
		sort.Stable(SortableEvents(list))
		var idx int = 0
		for idx < len(list) {
			if list[idx].NumTrace == 0 {
				idx++
				continue
			}
			if list[idx].EventType != 1 {
				idx++
				continue
			}
			var lower, upper uint64
			var curGroup prog.Group
			lower = list[idx].Ptr
			upper = lower + uint64(list[idx].Size)
			curGroup.NumGroups = 1
			newVal := atomic.AddUint64(&serv.maxGroupID, 1)
			curGroup.ID = newVal - 1
			for j := 0; j < prog.EVTRACK_EVENT_TYPES; j++ {
				curGroup.Events = append(curGroup.Events, make([]prog.EvtrackEvent, 0))
			}
			for idx < len(list) && list[idx].Ptr >= lower && list[idx].Ptr < upper {
				if list[idx].EventType > 2 && list[idx].NumTrace < 4 {
					idx++
					continue
				}
				fPath := serv.find_trigg_instruction(list[idx])
				if list[idx].EventType > 2 {
					spl := strings.Split(fPath, ":")
					lineNumber, _ := strconv.Atoi(spl[1])
					types := serv.llvmLookup.PerformLookup(spl[0], lineNumber, list[idx].EventType == prog.EVTRACK_EVENT_HEAP_READ)
					if len(types) > 1 {
						add_event(list[idx], &curGroup, types)
					} else if len(types) == 1 {
						list_idx := types[0] - 1
						list[idx].EventType = types[0]
						curGroup.Events[list_idx] = append(curGroup.Events[list_idx], list[idx])
					} else {
						list_idx := list[idx].EventType - 1
						curGroup.Events[list_idx] = append(curGroup.Events[list_idx], list[idx])
					}
				} else {
					list_idx := list[idx].EventType - 1
					curGroup.Events[list_idx] = append(curGroup.Events[list_idx], list[idx])
				}
				idx++
			}
			if !serv.dropGroup(&curGroup) {
				res = append(res, &curGroup)
				kept++
			} else {
				dropped++
			}
		}
	}
	serv.cacheMu.Lock()
	serv.groupsDropp += dropped
	serv.groupsKept += kept
	serv.cacheMu.Unlock()
	return res
}

func add_event(evt prog.EvtrackEvent, group *prog.Group, types []prog.EvtrackEventType) {
	// We never change the arguments of an event, we copy it when generating a syscall.
	// This means that it should not be a problem if two events point to the same argtree.
	// -> copying becomes a lot easier
	for _, t := range types {
		var event prog.EvtrackEvent
		event.EventId = evt.EventId
		event.EventType = t
		event.InstrId = evt.InstrId
		event.NumTrace = evt.NumTrace
		event.ObjId = evt.ObjId
		event.Ptr = evt.Ptr
		event.Size = evt.Size
		event.Syscall = evt.Syscall
		event.TimeStamp = evt.TimeStamp
		event.Trace = make([]uint32, len(evt.Trace))
		copy(event.Trace, evt.Trace)
		event.Args = make([]prog.Arg, len(evt.Args))
		copy(event.Args, evt.Args)
		group.Events[t-1] = append(group.Events[t-1], event)
	}
}

func (serv *RPCServer) dropGroup(group *prog.Group) bool {
	subsys := serv.find_subsystem(group)

	serv.collect_shared_access_stats(group, subsys)

	serv.cacheMu.Lock()
	defer serv.cacheMu.Unlock()

	prob := int(float64(100) * serv.subsysProbs[subsys])
	if rand.Intn(100) < prob {
		serv.subsysStats[subsys] += 1
		return false
	}
	return true
}

func (serv *RPCServer) collect_shared_access_stats(group *prog.Group, subsys string) {
	num_events := 0
	for _, evlist := range group.Events {
		num_events += len(evlist)
	}
	if num_events > 1 {
		serv.statsMu.Lock()
		serv.shared_objects += uint64(1)
		serv.shared_accesses += uint64(num_events)
		serv.shared_acc_subsys[subsys] += uint64(num_events)
		serv.statsMu.Unlock()
	} else {
		serv.statsMu.Lock()
		serv.single_acc += uint64(1)
		serv.statsMu.Unlock()
	}
}

func (serv *RPCServer) query_addr2line(address uint32) (string, error) {
	serv.addrMu.Lock()
	defer serv.addrMu.Unlock()

	addr := []byte(strconv.FormatUint(uint64(address) + 0xffffffff00000000, 16) + "\n")
	num, err := serv.addrIn.Write(addr)
	if err != nil {
		return "", err
	}

	newlines := 0
	resp := ""
	for newlines < 2 {
		var a []byte = make([]byte, 1)
		num, err = serv.addrOut.Read(a)
		if num == 0 {
			if err != nil && err != io.EOF {
				return "", err
			}
			break
		}
		resp += string(a[:])
		if a[0] == '\n' {
			newlines++
		}
	}
	return resp, nil
}

// Find triggering instruction and return file and line number in addr2line style
func (serv *RPCServer) find_trigg_instruction(evt prog.EvtrackEvent) string {
	api_names := []string{"__kasan_kmalloc", "kmem_cache_alloc_trace",
		"kfree", "slab_post_alloc_hook", "kmalloc_array", "kcalloc",
		"kzalloc", "kmalloc", "slab_free_freelist_hook", "__kasan_slab_free",
		"__vmalloc_node", "__asan_load1", "__asan_load2", "__asan_load4",
		"__asan_load8", "__asan_store1", "__asan_store2", "__asan_store4",
		"__asan_store8", "kmem_cache_free", "__kmalloc",
		"kmem_cache_alloc_node", "__kmalloc_track_caller", "kvmalloc_node",
		"kmalloc_node", "__vmalloc_node_range", "__kmalloc_node",
		"kmem_cache_alloc_node_trace", "kvfree", "check_memory_region",
		"kmem_cache_alloc", "memory_is_poisoned_2_4_8",
		"check_memory_region_inline", "kasan_mem_to_shadow", "is_handle_aborted"};
	misses := uint64(0)
	hits := uint64(0)
	var file string
	var prev_bound bool = true
	for i := uint32(2); i < evt.NumTrace; i++ {
		serv.cacheMu.Lock()
		_, ok := (serv.apiCache)[evt.Trace[i]]
		serv.cacheMu.Unlock()
		if ok {
			prev_bound = true
			continue
		}

		serv.cacheMu.Lock()
		val, ok := (serv.subsysCache)[evt.Trace[i]]
		serv.cacheMu.Unlock()
		if !ok {
			misses++
			out_s, err := serv.query_addr2line(evt.Trace[i])
			if err != nil {
				continue
			}
			splitted := strings.Split(out_s, "\n")
			found := false
			for _, api := range api_names {
				if splitted[0] == api {
					prev_bound = true
					found = true
					break
				}
			}
			if found {
				serv.cacheMu.Lock()
				(serv.apiCache)[evt.Trace[i]] = true
				serv.cacheMu.Unlock()
				continue
			}
			// serv.cfg["kernelDir"] does not end with a trailing frontslash ('/') character, hence +1 adjustment
			splitted[1] = splitted[1][len(serv.unpackedCfg["kernelDir"]) + 1:]

			serv.cacheMu.Lock()
			(serv.subsysCache)[evt.Trace[i]] = splitted[1]
			serv.cacheMu.Unlock()
			if prev_bound {
				evt.InstrId = i
				file = splitted[1]
				prev_bound = false
			}
		} else {
			hits++
			if prev_bound {
				evt.InstrId = i
				file = val
				prev_bound = false
			}
		}
	}
	serv.cacheMu.Lock()
	serv.cacheMisses += misses
	serv.cacheHit += hits
	serv.cacheMu.Unlock()
	return file
}

func (serv *RPCServer) find_subsystem(group *prog.Group) string {
	api_names := []string{"__kasan_kmalloc", "kmem_cache_alloc_trace",
		"kfree", "slab_post_alloc_hook", "kmalloc_array", "kcalloc",
		"kzalloc", "kmalloc", "slab_free_freelist_hook", "__kasan_slab_free",
		"__vmalloc_node", "__asan_load1", "__asan_load2", "__asan_load4",
		"__asan_load8", "__asan_store1", "__asan_store2", "__asan_store4",
		"__asan_store8", "kmem_cache_free", "__kmalloc",
		"kmem_cache_alloc_node", "__kmalloc_track_caller", "kvmalloc_node",
		"kmalloc_node", "__vmalloc_node_range", "__kmalloc_node",
		"kmem_cache_alloc_node_trace", "kvfree", "check_memory_region",
		"kmem_cache_alloc", "memory_is_poisoned_2_4_8",
		"check_memory_region_inline", "kasan_mem_to_shadow", "is_handle_aborted"};
	subs := make(map[string]uint32)
	misses := uint64(0)
	hits := uint64(0)
	for _, evtlist := range group.Events {
		for _, evt := range evtlist {
			var subsys string
			var prev_bound bool = true
			for i := uint32(evt.InstrId); i < evt.NumTrace; i++ {
				serv.cacheMu.Lock()
				_, ok := (serv.apiCache)[evt.Trace[i]]
				serv.cacheMu.Unlock()
				if ok {
					prev_bound = true
					continue
				}

				serv.cacheMu.Lock()
				val, ok := (serv.subsysCache)[evt.Trace[i]]
				serv.cacheMu.Unlock()
				if !ok {
					misses++
					out_s, err := serv.query_addr2line(evt.Trace[i])
					if err != nil {
						continue
					}
					splitted := strings.Split(out_s, "\n")
					found := false
					for _, api := range api_names {
						if splitted[0] == api {
							prev_bound = true
							found = true
							break
						}
					}
					if found {
						serv.cacheMu.Lock()
						(serv.apiCache)[evt.Trace[i]] = true
						serv.cacheMu.Unlock()
						continue
					}
					// serv.cfg["kernelDir"] does not end with a trailing frontslash ('/') character, hence +1 adjustment
					splitted[1] = splitted[1][len(serv.unpackedCfg["kernelDir"]) + 1:]
					serv.cacheMu.Lock()
					(serv.subsysCache)[evt.Trace[i]] = splitted[1]
					serv.cacheMu.Unlock()

					splitted = strings.Split(splitted[1], "/")
					if splitted[0] == "." && prev_bound == true {
						prev_bound = true
						continue
					}
					if prev_bound {
						subsys = splitted[0]
						prev_bound = false
					}
				} else {
					hits++
					splitted := strings.Split(val, "/")
					if splitted[0] == "." && prev_bound {
						prev_bound = true
						continue
					}
					if prev_bound {
						subsys = splitted[0]
						prev_bound = false
					}
				}
			}
			v, o := subs[subsys]
			if !o {
				subs[subsys] = 1
			} else {
				subs[subsys] = v + 1
			}
		}
	}
	max := uint32(0)
	name := ""
	for k, v := range subs {
		if v > max {
			max = v
			name = k
		}
	}
	serv.cacheMu.Lock()
	serv.cacheMisses += misses
	serv.cacheHit += hits
	serv.cacheMu.Unlock()
	return name
}

/*
 * Find and merge related groups.
 *
 * Returns a list of merged groups and a list of groups, which changed during
 * merging, and a list of GroupIDs, which were deleted.
 */
func (serv *RPCServer) find_merging_groups(groups []*prog.Group, num_new uint64) ([]*prog.Group, []prog.Result) {
	/*
	* Algorithm overview:
	*  - Step 1: Interpret all groups as nodes of an undirected graph. Two nodes
	*            are connected, if they are mergeable. Build the adjacency list
	*            of this graph.
	*  - Step 2: Use the standard graph algorithm for finding connected
	*            components in the graph (based on DFS).
	*  - Step 3: Each component represents one group. Merge all groups in this
	*            into the final big group.
	 */
	var adj_list [][]int = make([][]int, len(groups))
	var visited []bool = make([]bool, len(groups))
	for i := 0; i < len(adj_list); i++ {
		adj_list[i] = make([]int, 0)
		visited[i] = false
	}
	var connected_comp [][]int = make([][]int, 0)
	var merges []int
	var routines int = 30
	var results chan int
	results = make(chan int, routines)
	var pairs chan []int = make(chan []int, 2*routines)
	var expected, received int = 0, 0
	var helpers_finished int = 0

	// Step 1 - Build adjacency list
	for i := 0; i < routines; i++ {
		go step1_helper(i, routines, num_new, groups, results, pairs)
	}
	for helpers_finished < routines || received < expected {
		select {
		case pair := <-pairs:
			a := pair[0]
			b := pair[1]
			adj_list[a] = append(adj_list[a], b)
			adj_list[b] = append(adj_list[b], a)
			received++
		case found := <-results:
			expected += found
			helpers_finished++
		}
	}

	// Step 2 - Find connected components
	for i := 0; i < len(groups); i++ {
		if !visited[i] {
			merges, visited = step2_helper(i, visited, adj_list)
			connected_comp = append(connected_comp, merges)
		}
	}

	// Setp 3 - Merging component groups
	var merged_groups []*prog.Group = make([]*prog.Group, len(connected_comp))
	routines = 15
	tasks := make(chan int, routines*2) // shared queue of to be merged groups
	for i := 0; i < routines*2 && i < len(connected_comp); i++ {
		tasks <- i
	}
	var merge_results chan prog.Result = make(chan prog.Result, routines)

	for i := 0; i < routines; i++ {
		go serv.step3_helper(tasks, num_new, merge_results, groups, connected_comp)
	}

	var mergedRes []prog.Result = make([]prog.Result, len(connected_comp))
	var next_ind int = routines * 2
	for i := 0; i < len(connected_comp); i++ {
		mergedRes[i] = <-merge_results
		merged_groups[i] = mergedRes[i].Res
		if next_ind < len(connected_comp) {
			tasks <- next_ind
			next_ind++
		} else {
			tasks <- -1
		}
	}

	return merged_groups, mergedRes
}

func step1_helper(start int, step int, num_new uint64, groups []*prog.Group, results chan int, pairs chan []int) {
	var found int = 0
	for i := start; uint64(i) < num_new; i = i + step {
		for j := i + 1; j < len(groups); j++ {
			if check_merge(groups[i], groups[j]) {
				tmp := make([]int, 2)
				tmp[0] = i
				tmp[1] = j
				pairs <- tmp
				found++
			}
		}
	}
	results <- found
}

func step2_helper(index int, visited []bool, adj_list [][]int) ([]int, []bool) {
	visited[index] = true
	var component []int = make([]int, 0)
	var tmp []int
	for _, j := range adj_list[index] {
		if !visited[j] {
			tmp, visited = step2_helper(j, visited, adj_list)
			component = append(component, tmp...)
		}
	}
	component = append(component, index)
	return component, visited
}

func (serv *RPCServer) step3_helper(tasks chan int, num_new uint64, results chan prog.Result, groups []*prog.Group, connected_comp [][]int) {
	for {
		index := <-tasks
		if index == -1 {
			tasks <- -1
			break
		}
		var res prog.Result
		comp := connected_comp[index]
		temp := groups[comp[0]]
		if len(comp) == 1 {
			res.Res = temp
			if uint64(comp[0]) >= num_new {
				res.Changed = false
			} else {
				res.Changed = true
			}
			results <- res
			continue
		}
		tmp_list := make([]*prog.Group, len(comp))
		tmp_list[0] = groups[comp[0]]
		min := comp[0]
		for i := 1; i < len(comp); i++ {
			tmp_list[i] = groups[comp[i]]
			if groups[min].ID > groups[comp[i]].ID {
				if uint64(min) >= num_new {
					res.Deleted = append(res.Deleted, groups[min].ID)
				}
				min = comp[i]
			} else {
				if uint64(comp[i]) >= num_new {
					res.Deleted = append(res.Deleted, groups[comp[i]].ID)
				}
			}
		}
		res.Res = serv.merge_groups(tmp_list)
		res.Changed = true
		results <- res
		tmp_list = nil
	}
}

// Check if two groups can be merged
func check_merge(a *prog.Group, b *prog.Group) bool {
	for i := 0; i < len(a.Events); i++ {
		for _, evt := range a.Events[i] {
			for _, ref_evt := range b.Events[i] {
				if equal(evt, ref_evt) {
					return true
				}
			}
		}
	}
	return false
}

func equal(evt1 prog.EvtrackEvent, evt2 prog.EvtrackEvent) bool {
	if evt1.EventType != evt2.EventType {
		return false
	}
	if evt1.NumTrace != evt2.NumTrace {
		return false
	}
	for i := uint32(0); i < evt1.NumTrace; i++ {
		if evt1.Trace[i] != evt2.Trace[i] {
			return false
		}
	}
	return true
}

func (serv *RPCServer) merge_groups(list []*prog.Group) *prog.Group {
	// sync with initialization of fuzzer
	serv.groupMu.Lock()
	defer serv.groupMu.Unlock()
	var res prog.Group
	res.ID = list[0].ID
	for i := 0; i < prog.EVTRACK_EVENT_TYPES; i++ {
		res.Events = append(res.Events, make([]prog.EvtrackEvent, 0))
	}
	for _, grp := range list {
		for i := 0; i < len(res.Events); i++ {
			res.Events[i] = append(res.Events[i], grp.Events[i]...)
		}
		res.NumGroups += grp.NumGroups
		if res.ID > grp.ID {
			res.ID = grp.ID
		}
	}
	return &res
}

func filter_groups(groups []*prog.Group) []*prog.Group {
	var routines int = 30
	var finished chan *prog.Group = make(chan *prog.Group, 2*routines)
	for i := 0; i < routines; i++ {
		go filter_helper(i, routines, groups, finished)
	}
	result := make([]*prog.Group, len(groups))
	for i := 0; i < len(groups); i++ {
		result[i] = <-finished
	}
	return result
}

func filter_helper(i int, routines int, groups []*prog.Group, finished chan *prog.Group) {
	for ; i < len(groups); i = i + routines {
		g := groups[i]
		var newGroup prog.Group
		newGroup.Events = make([][]prog.EvtrackEvent, prog.EVTRACK_EVENT_TYPES)
		for j := 0; j < len(g.Events); j++ {
			tmp := remove_duplicates(g.Events[j])
			newGroup.Events[j] = tmp
		}
		newGroup.ID = g.ID
		newGroup.NumGroups = g.NumGroups
		finished <- &newGroup
	}
}

func remove_duplicates(evts []prog.EvtrackEvent) []prog.EvtrackEvent {
	var newlist []prog.EvtrackEvent = make([]prog.EvtrackEvent, 0)
	var duplicate bool = false
	for i := int(0); i < len(evts); i++ {
		duplicate = false
		for j := int(0); j < len(newlist); j++ {
			eq := equal(evts[i], newlist[j])
			if eq {
				duplicate = true
				break
			}
		}
		if !duplicate {
			newlist = append(newlist, evts[i])
		}
	}
	return newlist
}
