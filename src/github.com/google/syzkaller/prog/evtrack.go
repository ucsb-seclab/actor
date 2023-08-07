package prog

import (
	"bytes"
	"encoding/gob"
	"math/rand"
	"os"
	"sort"
	"sync"
)

type EvtrackEventType uint32
type Size_t uint32

const (
	NR_MAX_TRACE_ENTRIES             = 32 // Maximum number of stack trace entries in the context stored
	EVTRACK_EVENT_HEAP_ALLOCATION    = 1  // Heap allocations, e.g. kmalloc()
	EVTRACK_EVENT_HEAP_DEALLOCATION  = 2  // Heap deallocations, e.g. kfree()
	EVTRACK_EVENT_HEAP_READ          = 3  // Heap read
	EVTRACK_EVENT_HEAP_WRITE         = 4  // Heap write
	EVTRACK_EVENT_HEAP_POINTER_READ  = 5  // Heap read from pointer value
	EVTRACK_EVENT_HEAP_POINTER_WRITE = 6  // Heap write to pointer value
	EVTRACK_EVENT_HEAP_INDEX_READ    = 7  // Heap read from index value
	EVTRACK_EVENT_HEAP_INDEX_WRITE   = 8  // Heap write to index value
	EVTRACK_EVENT_TYPES              = 8  // Number of different event types
	GROUPS_PER_VM                    = 400 // Number of groups assigned to a VM
)

type EvtrackEvent struct {
	EventId   uint32                       // Monotonically increasing event id
	EventType EvtrackEventType             // Type of the event
	Ptr       uint64                       // Pointer associated to the event
	Size      Size_t                       // Size associated to the event
	NumTrace  uint32                       // Number of entries in the stack trace
	TimeStamp uint64                       // Nano-seconds
	ObjId     uint32                       // the event_id of the object this event is related to
	InstrId   uint32                       // the id of the instruction that triggers this event
	Trace     []uint32                     // Stack-trace leading to the event
	Syscall   string                       // Systemcall triggering the event (not recorded by the kernel))
	Args      []Arg                        // Arguments of the system call (not recorded by the kernel)
}

type Batch struct {
	Size      uint64
	Events    [][]EvtrackEvent
}

type Group struct {
	ID        uint64           // Arbitrary ID
	NumGroups uint32           // Number of initial groups merged together
	Events    [][]EvtrackEvent // The events of this group separated by type
}

type StratEntry struct {
	EventType EvtrackEventType
	ID        int64
	Repeat    string
}

type Strategy []StratEntry

type EvTrackState struct {
	mu         sync.Mutex
	groups     []*Group
	groupInd   int
	groupUsed  map[uint64]bool
	newUsed    map[uint64]bool
	evChoice   *EvChoiceTable
	strategies []Strategy

}

type GroupLookup struct {
	GroupID   uint64
	EventType EvtrackEventType
}

type Result struct {
	Res     *Group
	Changed bool
	Deleted []uint64
}

type SortableGroups []*Group

func (g SortableGroups) Len() int {
	return len(g)
}

func (g SortableGroups) Swap(i, j int) {
	g[i], g[j] = g[j], g[i]
}

func (g SortableGroups) Less(i, j int) bool {
	return g[i].ID < g[j].ID
}

func InitEvTrackState() *EvTrackState {
	var state EvTrackState
	state.groups = make([]*Group, 0)
	state.groupInd = 0
	state.groupUsed = make(map[uint64]bool)
	state.newUsed = make(map[uint64]bool)
	state.strategies = getDefaultStrategies()
	return &state
}

func getDefaultStrategies() []Strategy {
	var strats = make([]Strategy, 16)

	// uaf: alloc, free, use
	strats[0] = make(Strategy, 3)
	strats[0][0].ID = 1
	strats[0][0].EventType = EvtrackEventType(0)
	strats[0][1].ID = 2
	strats[0][1].EventType = EvtrackEventType(1)
	strats[0][2].ID = 3
	strats[0][2].EventType = EvtrackEventType(2)
	// uaf: alloc, free, use
	strats[1] = make(Strategy, 3)
	strats[1][0].ID = 1
	strats[1][0].EventType = EvtrackEventType(0)
	strats[1][1].ID = 2
	strats[1][1].EventType = EvtrackEventType(1)
	strats[1][2].ID = 3
	strats[1][2].EventType = EvtrackEventType(3)
	// uaf: alloc, free, use
	strats[2] = make(Strategy, 3)
	strats[2][0].ID = 1
	strats[2][0].EventType = EvtrackEventType(0)
	strats[2][1].ID = 2
	strats[2][1].EventType = EvtrackEventType(1)
	strats[2][2].ID = 3
	strats[2][2].EventType = EvtrackEventType(4)
	// uaf: alloc, free, use
	strats[3] = make(Strategy, 3)
	strats[3][0].ID = 1
	strats[3][0].EventType = EvtrackEventType(0)
	strats[3][1].ID = 2
	strats[3][1].EventType = EvtrackEventType(1)
	strats[3][2].ID = 3
	strats[3][2].EventType = EvtrackEventType(5)
	// uaf: alloc, free, use
	strats[4] = make(Strategy, 3)
	strats[4][0].ID = 1
	strats[4][0].EventType = EvtrackEventType(0)
	strats[4][1].ID = 2
	strats[4][1].EventType = EvtrackEventType(1)
	strats[4][2].ID = 3
	strats[4][2].EventType = EvtrackEventType(6)
	// uaf: alloc, free, use
	strats[5] = make(Strategy, 3)
	strats[5][0].ID = 1
	strats[5][0].EventType = EvtrackEventType(0)
	strats[5][1].ID = 2
	strats[5][1].EventType = EvtrackEventType(1)
	strats[5][2].ID = 3
	strats[5][2].EventType = EvtrackEventType(7)

	// double free: alloc, free, free
	strats[6] = make(Strategy, 3)
	strats[6][0].ID = 1
	strats[6][0].EventType = EvtrackEventType(0)
	strats[6][1].ID = 2
	strats[6][1].EventType = EvtrackEventType(1)
	strats[6][2].ID = 3
	strats[6][2].EventType = EvtrackEventType(1)

	// invalid free: free
	strats[7] = make(Strategy, 1)
	strats[7][0].ID = 1
	strats[7][0].EventType = EvtrackEventType(1)

	// overflow/underflow: (idx write)*, idx read
	strats[8] = make(Strategy, 3)
	strats[8][0].ID = 1
	strats[8][0].EventType = EvtrackEventType(1)
	strats[8][1].ID = 1
	strats[8][1].Repeat = "*"
	strats[8][1].EventType = EvtrackEventType(7)
	strats[8][2].ID = 2
	strats[8][2].EventType = EvtrackEventType(6)
	// overflow/underflow: (ptr write)*, ptr read
	strats[9] = make(Strategy, 3)
	strats[9][0].ID = 1
	strats[9][0].EventType = EvtrackEventType(1)
	strats[9][1].ID = 1
	strats[9][1].Repeat = "*"
	strats[9][1].EventType = EvtrackEventType(5)
	strats[9][2].ID = 2
	strats[9][2].EventType = EvtrackEventType(4)

	// null-ptr-deref (1)/ uninit read: alloc, read
	strats[10] = make(Strategy, 2)
	strats[10][0].ID = 1
	strats[10][0].EventType = EvtrackEventType(0)
	strats[10][1].ID = 2
	strats[10][1].EventType = EvtrackEventType(2)
	// null-ptr-deref (1)/ uninit read: alloc, idx read
	strats[11] = make(Strategy, 2)
	strats[11][0].ID = 1
	strats[11][0].EventType = EvtrackEventType(0)
	strats[11][1].ID = 2
	strats[11][1].EventType = EvtrackEventType(6)
	// null-ptr-deref (1)/ uninit read: alloc, ptr read
	strats[12] = make(Strategy, 2)
	strats[12][0].ID = 1
	strats[12][0].EventType = EvtrackEventType(0)
	strats[12][1].ID = 2
	strats[12][1].EventType = EvtrackEventType(4)

	// null-ptr-deref (2): x allocs, x frees
	strats[13] = make(Strategy, 2)
	strats[13][0].ID = 1
	strats[13][0].Repeat = "r1"
	strats[13][0].EventType = EvtrackEventType(0)
	strats[13][1].ID = 2
	strats[13][1].Repeat = "r1"
	strats[13][1].EventType = EvtrackEventType(1)

	// memleak: alloc*
	strats[14] = make(Strategy, 1)
	strats[14][0].ID = -1
	strats[14][0].Repeat = "*"
	strats[14][0].EventType = EvtrackEventType(0)

	// memleak: alloc -> ptr write -> free
	strats[15] = make(Strategy, 3)
	strats[15][0].ID = 1
	strats[15][0].EventType = EvtrackEventType(0)
	strats[15][1].ID = 2
	strats[15][1].EventType = EvtrackEventType(5)
	strats[15][2].ID = 3
	strats[15][2].EventType = EvtrackEventType(1)

	return strats
}

func (state *EvTrackState) AddStrategies(strats []Strategy) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.strategies = append(state.strategies, strats...)
}

func (state *EvTrackState) BuildEvChoiceTable(target *Target, enabled map[*Syscall]bool) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.evChoice = state.buildEvChoiceTableImpl(target, enabled)
}

func (state *EvTrackState) GetNewUsed() map[uint64]bool {
	state.mu.Lock()
	defer state.mu.Unlock()

	res := state.newUsed
	state.newUsed = make(map[uint64]bool)
	return res
}

func (state *EvTrackState) GetLength() int {
	state.mu.Lock()
	defer state.mu.Unlock()

	return len(state.groups)
}

func checkSyscalls(results []Result, byName map[string]bool) ([]Result, []uint64, []uint64) {
	todelete := make([]int, 0)
	for i, r := range results {
		g := r.Res
		var stop bool = false
		for _, evlist := range g.Events {
			for _, event := range evlist {
				if !byName[event.Syscall] {
					todelete = append(todelete, i)
					stop = true
					break
				}
			}
			if stop {
				break
			}
		}
	}
	deletedIDs := make([]uint64, len(todelete))
	moreDeletes := make([]uint64, 0)
	for i, _ := range todelete {
		s := todelete[len(todelete)-1-i]
		deletedIDs[i] = results[s].Res.ID
		moreDeletes = append(moreDeletes, results[s].Deleted...)
		if s == len(results) - 1 {
			results = results[:s]
		} else {
			results = append(results[:s], results[s+1:]...)
		}
	}
	return results, deletedIDs, moreDeletes
}

func (state *EvTrackState) DumpState(filename string) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(state.groups)
	if err != nil {
		return err
	}
	f.Write(buf.Bytes())
	return nil
}

func (state *EvTrackState) Update(changes []Result, target *Target, enabled map[*Syscall]bool, shouldBuildEvChoiceTable bool) []uint64 {
	if len(changes) == 0 {
		return []uint64{}
	}
	byName := make(map[string]bool)
	for c := range enabled {
		byName[c.Name] = true
	}
	changes, deletedIDs, moreDeletes := checkSyscalls(changes, byName)

	state.mu.Lock()
	defer state.mu.Unlock()
	// if state.groups is empty, sort the new list, delete everything, finished
	if len(state.groups) == 0 {
		for _, r := range changes {
			state.groups = append(state.groups, r.Res)
		}
		sort.Stable(SortableGroups(state.groups))
		state.groups = remove_duplicates(state.groups)
		for _, r := range changes {
			state.groups = perform_delete(state.groups, r.Deleted, false)
		}
	} else {
		for _, r := range changes {
			group := r.Res
			if group.ID > state.groups[len(state.groups)-1].ID {
				state.groups = append(state.groups, group)
				continue
			} else if group.ID < state.groups[0].ID {
				state.groups = append([]*Group{group}, state.groups...)
				continue
			}
			var min, max, middle int
			var found bool = false
			min = 0
			max = len(state.groups)
			for min <= max {
				middle = (min + max) / 2
				if group.ID > state.groups[middle].ID {
					min = middle + 1
				} else if group.ID < state.groups[middle].ID {
					max = middle - 1
				} else {
					state.groups[middle] = group
					found = true
					break
				}
			}
			if !found {
				// new group, either one group that was already here was merged into another one
				// or the fuzzer did not have enough groups assigned yet
				if group.ID > state.groups[middle].ID {
					state.groups = append(state.groups[:middle+2], state.groups[middle+1:]...)
					state.groups[middle+1] = group
				} else if group.ID < state.groups[middle].ID {
					state.groups = append(state.groups[:middle+1], state.groups[middle:]...)
					state.groups[middle] = group
				} else {
					os.Exit(1)
				}
			}
		}
		state.groups = remove_duplicates(state.groups)
		for _, r := range changes {
			if len(r.Deleted) > 0 {
				state.groups = perform_delete(state.groups, r.Deleted, false)
			}
		}
	}
	state.groups = perform_delete(state.groups, moreDeletes, false)
	// Update choice table in the same critical section along with the group information update
	if shouldBuildEvChoiceTable {
		state.evChoice = state.buildEvChoiceTableImpl(target, enabled)
	}
	return deletedIDs
}

func remove_duplicates(groups []*Group) []*Group {
	for i := 0; i < len(groups)-1; i++ {
		if groups[i].ID == groups[i+1].ID {
			if groups[i].NumGroups > groups[i+1].NumGroups {
				// I think this should not be possible
				os.Exit(1)
			}
			groups = append(groups[:i], groups[i+1:]...)
		}
	}
	return groups
}

func perform_delete(groups []*Group, to_delete []uint64, already_sorted bool) []*Group {
	if !already_sorted && len(to_delete) > len(groups) {
		// search each in the list and delete
		for _, id := range to_delete {
			var min, max, middle int
			min = 0
			max = len(groups) - 1
			for min <= max {
				middle = (min + max) / 2
				if middle >= len(groups) {
					break
				}
				if middle < 0 {
					break
				}
				if groups[middle].ID > id {
					max = middle - 1
				} else if groups[middle].ID < id {
					min = middle + 1
				} else {
					groups = append(groups[:middle], groups[middle+1:]...)
					break
				}
			}
		}
	} else {
		// sort to_delete and then go from front to back
		if !already_sorted {
			sort.Slice(to_delete, func(i, j int) bool { return to_delete[i] < to_delete[j] })
		}
		var i, j int = 0, 0
		for i < len(to_delete) && j < len(groups) {
			if to_delete[i] < groups[j].ID {
				i++
			} else if to_delete[i] > groups[j].ID {
				j++
			} else {
				groups = append(groups[:j], groups[j+1:]...)
			}
		}
	}
	return groups
}

func (state *EvTrackState) GetID(id uint64) *Group {
	state.mu.Lock()
	defer state.mu.Unlock()

	return state.getIDImpl(id)
}

func (state *EvTrackState) getIDImpl(id uint64) *Group {
	var g *Group
	var min, max, middle int
	min, max = 0, len(state.groups)-1
	for min <= max {
		middle = (min + max) / 2
		if state.groups[middle].ID < id {
			min = middle + 1
		} else if state.groups[middle].ID > id {
			max = middle - 1
		} else {
			g = state.groups[middle]
			break
		}
	}
	if g == nil {
		panic("did not find group")
	}
	return g
}

func (state *EvTrackState) GetRandom(r *rand.Rand) *Group {
	state.mu.Lock()
	defer state.mu.Unlock()

	return state.getRandomImpl(r)
}

func (state *EvTrackState) getRandomImpl(r *rand.Rand) *Group {
	return state.groups[r.Intn(len(state.groups))]
}

func (state *EvTrackState) GetConditional(r *rand.Rand, f func(*Group) bool) *Group {
	state.mu.Lock()
	defer state.mu.Unlock()

	return state.getConditionalImpl(r, f)
}

func (state *EvTrackState) getConditionalImpl(r *rand.Rand, f func(*Group) bool) *Group {
	offset := r.Intn(len(state.groups))
	for i := 0; i < len(state.groups); i++ {
		g := state.groups[(i+offset)%len(state.groups)]
		if f(g) {
			return g
		}
	}
	return nil
}

func (state *EvTrackState) createMapping(target *Target) [][]GroupLookup {

	lookups := make([][]GroupLookup, len(target.Syscalls))
	for _, g := range state.groups {
		for _, evlist := range g.Events {
			for _, event := range evlist {
				call := target.SyscallMap[event.Syscall]
				if lookups[call.ID] == nil {
					lookups[call.ID] = make([]GroupLookup, 0)
				}
				lookups[call.ID] = append(lookups[call.ID], GroupLookup{g.ID, event.EventType})
			}
		}
	}
	return lookups
}
