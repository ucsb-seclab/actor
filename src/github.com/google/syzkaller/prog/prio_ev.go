
package prog

import (
	"math/rand"
	"sort"
	"strconv"
)

type EvChoiceTable struct {
	target   *Target
	lookups  [][]GroupLookup
	calls    []*Syscall
}

func (state *EvTrackState) buildEvChoiceTableImpl(target *Target, enabled map[*Syscall]bool) *EvChoiceTable {
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	for call := range enabled {
		if call.Attrs.Disabled {
			delete(enabled, call)
		}
	}
	var enabledSyscalls []*Syscall
	for c := range enabled {
		enabledSyscalls = append(enabledSyscalls, c)
	}
	if len(enabledSyscalls) == 0 {
		panic("no syscalls enabled")
	}
	sort.Slice(enabledSyscalls, func(i, j int) bool {
		return enabledSyscalls[i].ID < enabledSyscalls[j].ID
	})

	mapping := state.createMapping(target)
	return &EvChoiceTable{target, mapping, enabledSyscalls}
}


func (state *EvTrackState) chooseGroup(r *rand.Rand, previous int, inGeneration int) ([]string, [][]Arg) {
	state.mu.Lock()
	defer state.mu.Unlock()

	strat := state.strategies[r.Intn(len(state.strategies))]
	for inGeneration != -1 && len(strat) > RecommendedCalls - inGeneration {
		strat = state.strategies[r.Intn(len(state.strategies))]
	}
	var g *Group
	if previous < 0 {
		g = state.getConditionalImpl(r, hasAllEventTypes)
	} else {
		lookups := state.evChoice.lookups[previous]
		if len(lookups) == 0 {
			return nil, nil
		}
		randOffset := r.Intn(len(lookups))
		var actLookup GroupLookup
		for i := 0; i < len(lookups); i++ {
			ind := (i + randOffset) % len(lookups)
			actLookup = lookups[ind]
			g = state.getIDImpl(actLookup.GroupID)
			if hasAllNecessaryEventTypes(g, strat) {
				break
			} else {
				g = nil
			}
		}
	}
	if g == nil {
		return nil, nil
	}
	_, seen := state.groupUsed[g.ID]
	if !seen {
		state.groupUsed[g.ID] = true
		state.newUsed[g.ID] = true
	}
	gadgets := make(map[int64]EvtrackEvent)
	randomNums := make(map[string]int)
	var names []string = make([]string, 0)
	var args [][]Arg = make([][]Arg, 0)
	var present bool
	var evt EvtrackEvent
	maxAdditions := RecommendedCalls
	if inGeneration != -1 {
		maxAdditions = RecommendedCalls - inGeneration - len(strat)
	}
	for _, entry := range strat {
		ev_type := entry.EventType
		num := 1
		if entry.Repeat == "*" {
			if maxAdditions > 0 {
				num = r.Intn(maxAdditions)
			}
		}  else if len(entry.Repeat) > 0 && entry.Repeat[0] == 'r' {
			num, present = randomNums[entry.Repeat]
			if !present {
				if maxAdditions/2 > 0 {
					num = r.Intn(maxAdditions/2)
				}
				randomNums[entry.Repeat] = num
			}
		} else if len(entry.Repeat) > 0 {
			num, _ = strconv.Atoi(entry.Repeat)
		}
		evt, present = gadgets[entry.ID]
		if !present && entry.ID >= 0 {
			evt = g.Events[ev_type][r.Intn(len(g.Events[ev_type]))]
			gadgets[entry.ID] = evt
		}
		if entry.Repeat != "" && entry.ID < 0 {
			// repeat with random events
			for i := 0; i < num; i++ {
				evt = g.Events[ev_type][r.Intn(len(g.Events[ev_type]))]
				names = append(names, evt.Syscall)
				args = append(args, evt.Args)
			}
		} else { 
			// repeat one event
			for i := 0; i < num; i++ {
				names = append(names, evt.Syscall)
				args = append(args, evt.Args)
			}
		}
	}

	return names, args
}

func collectValidStrats(g *Group, strats []Strategy) []Strategy {
	res := make([]Strategy, 0)
	for _, s := range strats {
		if hasAllNecessaryEventTypes(g, s) {
			res = append(res, s)
		}
	}
	return res
}

func hasAllNecessaryEventTypes(g *Group, strat Strategy) bool {
	needed := make([]bool, EVTRACK_EVENT_TYPES)
	for _, stEntry := range strat {
		needed[int(stEntry.EventType)] = true
	}
	for i := range g.Events {
		if len(g.Events[i]) > 0 {
			needed[i] = false
		}
	}
	for _, val := range needed {
		if val {
			return false
		}
	}
	return true;
}

func hasAllEventTypes(g *Group) bool {
	for i := 0; i < len(g.Events); i++ {
		if len(g.Events[i]) == 0 {
			return false
		}
	}
	return true
}
