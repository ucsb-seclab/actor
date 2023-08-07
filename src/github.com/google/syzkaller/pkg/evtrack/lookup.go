package evtrack;

import (
	"os"
	"fmt"
	"bufio"
	"strings"
	"strconv"
	"path/filepath"

	"github.com/google/syzkaller/prog"
)

type LLVMFileLookup map[int][]prog.EvtrackEventType
type LLVMLookup map[string]LLVMFileLookup

func LoadLLVMInfo(path string) *LLVMLookup {
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := make([]string, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	res := make(LLVMLookup)
	for _, line := range lines {
		if !check_line(line) {
			continue
		}
		tokens := strings.Split(line, " ")
		if len(tokens) != 3 {
			fmt.Println(line)
			continue
		}

		file_info := strings.Split(tokens[2], ":")
		if len(file_info) != 3 {
			fmt.Println(line)
			continue
		}

		// some paths have ..
		file_path := filepath.Clean(file_info[1])
		file_lookup, ok := res[file_path]
		if !ok {
			file_lookup = make(LLVMFileLookup)
		}
		line_number, err := strconv.Atoi(file_info[2])
		if err != nil {
			fmt.Println("parsing", tokens[2], "line number", err)
			continue
		}
		res[file_path] = addEntry(file_lookup, line_number, tokens[0])
	}

	return &res
}

func addEntry(file_lookup LLVMFileLookup, line_number int, access_type string) LLVMFileLookup {
	type_list, ok := file_lookup[line_number]
	if !ok {
		type_list = make([]prog.EvtrackEventType, 0)
	}

	// we don't want the same type multiple times in the list
	for _, val := range type_list {
		if val == getTypeForString(access_type) {
			file_lookup[line_number] = type_list
			return file_lookup
		}
	}

	type_list = append(type_list, getTypeForString(access_type))
	file_lookup[line_number] = type_list
	return file_lookup
}

func getTypeForString(access_type string) prog.EvtrackEventType {
	switch access_type {
	case "ptrwrite":
		return prog.EVTRACK_EVENT_HEAP_POINTER_WRITE
	case "ptrread":
		return prog.EVTRACK_EVENT_HEAP_POINTER_READ
	case "idxread":
		return prog.EVTRACK_EVENT_HEAP_INDEX_READ
	case "idxwrite":
		return prog.EVTRACK_EVENT_HEAP_INDEX_WRITE
	default:
		panic("unknown access type")
	}
}

func check_line(line string) bool {
	return strings.HasPrefix(line, "ptr") || strings.HasPrefix(line, "idx")
}

func (lookup *LLVMLookup) PerformLookup(file string, line_number int, read bool) []prog.EvtrackEventType {
	file_clean := filepath.Clean(file)
	file_lookup, ok := (*lookup)[file_clean]
	if !ok {
		return nil
	}
	numbers := []int{line_number-1, line_number, line_number+1}
	intermediate := make(map[prog.EvtrackEventType]bool)
	for _, num := range numbers {
		types, ok := file_lookup[num]
		if ok {
			for _, t := range types {
				if (read && t == prog.EVTRACK_EVENT_HEAP_POINTER_READ) ||
					(read && t == prog.EVTRACK_EVENT_HEAP_INDEX_READ) ||
					(!read && t == prog.EVTRACK_EVENT_HEAP_POINTER_WRITE) ||
					(!read && t == prog.EVTRACK_EVENT_HEAP_INDEX_WRITE) {
					intermediate[t] = true
				}
			}
		}
	}
	res := make([]prog.EvtrackEventType, len(intermediate))
	i := 0
	for t := range intermediate {
		res[i] = t
		i++
	}
	return res
}
