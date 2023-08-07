package evtrack

import (
	"fmt"
	"bytes"
	"io/ioutil"
	"encoding/gob"

	"google.golang.org/protobuf/proto"
	"github.com/google/syzkaller/prog"
	pb "github.com/google/syzkaller/pkg/protobuf"
)

func EncodeBatchGob(batch prog.Batch) []byte {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(batch)
	if err != nil {
		fmt.Println("Encoding failed:", err)
		return nil
	}
	return buf.Bytes()
}

func DecodeBatchGob(data []byte) prog.Batch {
	var batch prog.Batch
	dec := gob.NewDecoder(bytes.NewBuffer(data))
	err := dec.Decode(&batch)
	if err != nil {
		fmt.Println("Decoding failed:", err)
	}
	return batch
}

func EncodeBatchPb(batch prog.Batch) []byte {
	var pbBatch *pb.Batch = batchToPb(batch)
	out, err := proto.Marshal(pbBatch)
	if err != nil {
		fmt.Println("Encoding failed:", err)
		return nil
	}
	return out
}

func DecodeBatchPb(data []byte) prog.Batch {
	pbBatch := &pb.Batch{}
	err := proto.Unmarshal(data, pbBatch)
	if err != nil {
		fmt.Println("Decoding failed:", err)
		return prog.Batch{}
	}
	return pbToBatch(pbBatch)
}

func EncodeProgsPb(progs [][]string) []byte {
	var progArr []*pb.Program
	for i := range progs {
		prog := &pb.Program{
			Syscalls: progs[i],
		}
		progArr = append(progArr, prog)
	}
	pbProgs := &pb.Programs{
		Progs: progArr,
	}
	out, err := proto.Marshal(pbProgs)
	if err != nil {
		fmt.Println("Encoding failed:", err)
		return nil
	}
	return out
}

func DecodeProgsPb(data []byte) [][]string {
	pbProgs := &pb.Programs{}
	err := proto.Unmarshal(data, pbProgs)
	if err != nil {
		fmt.Println("Decoding failed:", err)
		return [][]string{}
	}
	progs := make([][]string, 0)
	for i := range pbProgs.Progs {
		progs = append(progs, pbProgs.Progs[i].Syscalls)
	}
	return progs
}

func EncodeDeletedPb(ids []uint64) []byte {
	deleted := &pb.DeletedGroups{
		Deleted: ids,
	}
	out, err := proto.Marshal(deleted)
	if err != nil {
		fmt.Println("Encoding failed:", err)
		return nil
	}
	return out
}

func DecodeDeletedPb(data []byte) []uint64 {
	deleted := &pb.DeletedGroups{}
	err := proto.Unmarshal(data, deleted)
	if err != nil {
		fmt.Println("Decoding failed:", err)
		return []uint64{}
	}
	return deleted.Deleted
}

func EncodeChangedPb(groups []*prog.Group) []byte {
	groupsPb := groupsToPb(groups)
	out, err := proto.Marshal(groupsPb)
	if err != nil {
		fmt.Println("Encoding failed:", err)
		return nil
	}
	return out
}

func DecodeChangedPb(data []byte) []*prog.Group {
	groupsPb := &pb.ChangedGroups{}
	err := proto.Unmarshal(data, groupsPb)
	if err != nil {
		fmt.Println("Decoding failed:", err)
		return []*prog.Group{}
	}
	return pbToGroups(groupsPb)
}

func eventToPb(evt prog.EvtrackEvent) *pb.EvtrackEvent {
	var args []*pb.Arg
	for i := range evt.Args {
		args = append(args, argToPb(evt.Args[i]))
	}
	return &pb.EvtrackEvent{
		EventId: evt.EventId,
		EventType: uint32(evt.EventType),
		Ptr: evt.Ptr,
		Size: uint32(evt.Size),
		NumTrace: evt.NumTrace,
		Trace: evt.Trace,
		Syscall: evt.Syscall,
		Args: args,
	}
}

func pbToEvent(evt *pb.EvtrackEvent) prog.EvtrackEvent {
	var args []prog.Arg
	for i := range evt.Args {
		args = append(args, pbToArg(evt.Args[i]))
	}
	return prog.EvtrackEvent{
		EventId: evt.EventId,
		EventType: prog.EvtrackEventType(evt.EventType),
		Ptr: evt.Ptr,
		Size: prog.Size_t(evt.Size),
		NumTrace: evt.NumTrace,
		Trace: evt.Trace,
		Syscall: evt.Syscall,
		Args: args,
	}
}

func argToPb(a prog.Arg) *pb.Arg {
	switch a.(type) {
	case *prog.PointerArg:
		return ptrToPb(a.(*prog.PointerArg))
	case *prog.GroupArg:
		return groupArgToPb(a.(*prog.GroupArg))
	case *prog.ConstArg:
		return constToPb(a.(*prog.ConstArg))
	case *prog.UnionArg:
		return unionToPb(a.(*prog.UnionArg))
	case *prog.ResultArg:
		return resultToPb(a.(*prog.ResultArg))
	case *prog.DataArg:
		return dataToPb(a.(*prog.DataArg))
	}
	panic("unknown arg")
	return nil
}

func pbToArg(a *pb.Arg) prog.Arg {
	switch a.Subtype.(type) {
	case *pb.Arg_PtrArg:
		return pbToPtr(a)
	case *pb.Arg_GroupArg_:
		return pbToGroup(a)
	case *pb.Arg_ConstArg_:
		return pbToConst(a)
	case *pb.Arg_UnionArg_:
		return pbToUnion(a)
	case *pb.Arg_ResArg:
		return pbToResult(a)
	case *pb.Arg_DataArg_:
		return pbToData(a)
	}
	fmt.Printf("%T\n", a)
	fmt.Println(a)
	panic("unknown arg")
	return nil
}

func ptrToPb(a *prog.PointerArg) *pb.Arg {
	var res *pb.Arg
	if a.Res != nil {
		res = argToPb(a.Res)
	}
	return &pb.Arg{
		Ref: uint32(a.Ref),
		Dir: uint32(a.Dir),
		Subtype: &pb.Arg_PtrArg{
			PtrArg: &pb.Arg_PointerArg{
				Address: a.Address,
				VmaSize: a.VmaSize,
				Res: res,
			},
		},
	}
}

func pbToPtr(a *pb.Arg) prog.Arg {
	var res prog.Arg
	if a.Subtype.(*pb.Arg_PtrArg).PtrArg.Res != nil {
		res = pbToArg(a.Subtype.(*pb.Arg_PtrArg).PtrArg.Res)
	}
	return &prog.PointerArg{
		ArgCommon: prog.ArgCommon{
			Ref: prog.Ref(a.Ref),
			Dir: prog.Dir(a.Dir),
		},
		Address: a.Subtype.(*pb.Arg_PtrArg).PtrArg.Address,
		VmaSize: a.Subtype.(*pb.Arg_PtrArg).PtrArg.VmaSize,
		Res: res,
	}
}

func groupArgToPb(a *prog.GroupArg) *pb.Arg {
	if len(a.Inner) == 0 {
		return &pb.Arg{
			Ref: uint32(a.Ref),
			Dir: uint32(a.Dir),
			Subtype: &pb.Arg_GroupArg_{},
		}
	}
	var inner []*pb.Arg
	for i := range a.Inner {
		inner = append(inner, argToPb(a.Inner[i]))
	}
	return &pb.Arg{
		Ref: uint32(a.Ref),
		Dir: uint32(a.Dir),
		Subtype: &pb.Arg_GroupArg_{
			GroupArg: &pb.Arg_GroupArg{
				Inner: inner,
			},
		},
	}
}

func pbToGroup(a *pb.Arg) prog.Arg {
	if len(a.Subtype.(*pb.Arg_GroupArg_).GroupArg.Inner) == 0 {
		return &prog.GroupArg{
			ArgCommon: prog.ArgCommon{
				Ref: prog.Ref(a.Ref),
				Dir: prog.Dir(a.Dir),
			},
		}
	}
	pbGroupArg := a.Subtype.(*pb.Arg_GroupArg_).GroupArg
	var inner []prog.Arg
	for i := range pbGroupArg.Inner {
		inner = append(inner, pbToArg(pbGroupArg.Inner[i]))
	}
	return &prog.GroupArg{
		ArgCommon: prog.ArgCommon{
			Ref: prog.Ref(a.Ref),
			Dir: prog.Dir(a.Dir),
		},
		Inner: inner,
	}
}

func constToPb(a *prog.ConstArg) *pb.Arg {
	return &pb.Arg{
		Ref: uint32(a.Ref),
		Dir: uint32(a.Dir),
		Subtype: &pb.Arg_ConstArg_{
			ConstArg: &pb.Arg_ConstArg{
				Val: a.Val,
			},
		},
	}
}

func pbToConst(a *pb.Arg) prog.Arg {
	return &prog.ConstArg{
		ArgCommon: prog.ArgCommon{
			Ref: prog.Ref(a.Ref),
			Dir: prog.Dir(a.Dir),
		},
		Val: a.Subtype.(*pb.Arg_ConstArg_).ConstArg.Val,
	}
}

func unionToPb(a *prog.UnionArg) *pb.Arg {
	return &pb.Arg{
		Ref: uint32(a.Ref),
		Dir: uint32(a.Dir),
		Subtype: &pb.Arg_UnionArg_{
			UnionArg: &pb.Arg_UnionArg{
				ArgOption: argToPb(a.Option),
				Index: int32(a.Index),
			},
		},
	}
}

func pbToUnion(a *pb.Arg) prog.Arg {
	union := a.Subtype.(*pb.Arg_UnionArg_).UnionArg
	return &prog.UnionArg{
		ArgCommon: prog.ArgCommon{
			Ref: prog.Ref(a.Ref),
			Dir: prog.Dir(a.Dir),
		},
		Option: pbToArg(union.ArgOption),
		Index: int(union.Index),
	}
}

func resultToPb(a *prog.ResultArg) *pb.Arg {
	var res *pb.Arg_ResultArg = nil
	if a.Res != nil {
		res = resultToPb(a.Res).Subtype.(*pb.Arg_ResArg).ResArg
	}
	return &pb.Arg{
		Ref: uint32(a.Ref),
		Dir: uint32(a.Dir),
		Subtype: &pb.Arg_ResArg{
			ResArg: &pb.Arg_ResultArg{
				Res: res,
				OpDiv: a.OpDiv,
				OpAdd: a.OpAdd,
				Val: a.Val,
			},
		},
	}
}

func pbToResult(a *pb.Arg) prog.Arg {
	ret := &prog.ResultArg{
		ArgCommon: prog.ArgCommon{
			Ref: prog.Ref(a.Ref),
			Dir: prog.Dir(a.Dir),
		},
		OpDiv: a.Subtype.(*pb.Arg_ResArg).ResArg.OpDiv,
		OpAdd: a.Subtype.(*pb.Arg_ResArg).ResArg.OpAdd,
		Val: a.Subtype.(*pb.Arg_ResArg).ResArg.Val,
	}
	return ret
}

func dataToPb(a *prog.DataArg) *pb.Arg {
	dataArg := &pb.Arg_DataArg{}
	if a.Dir == prog.DirOut {
		dataArg.Size = a.Size()
	} else {
		dataArg.Data = a.Data()
	}
	result := &pb.Arg{
		Ref: uint32(a.Ref),
		Dir: uint32(a.Dir),
		Subtype: &pb.Arg_DataArg_{
			DataArg: dataArg,
		},
	}
	return result
}

func pbToData(a *pb.Arg) prog.Arg {
	dataArg := a.Subtype.(*pb.Arg_DataArg_).DataArg
	result := &prog.DataArg{
		ArgCommon: prog.ArgCommon{
			Ref: prog.Ref(a.Ref),
			Dir: prog.Dir(a.Dir),
		},
	}
	if prog.Dir(a.Dir) == prog.DirOut {
		result.SetSize(dataArg.Size)
	} else {
		result.SetData(dataArg.Data)
	}
	return result
}

func batchToPb(b prog.Batch) *pb.Batch {
	var evts []*pb.EventsList = make([]*pb.EventsList, len(b.Events))
	for i, evtList := range b.Events {
		var events []*pb.EvtrackEvent = make([]*pb.EvtrackEvent, len(evtList))
		for j, evt := range evtList {
			events[j] = eventToPb(evt)
		}
		evts[i] = &pb.EventsList{
			Events: events,
		}
	}
	return &pb.Batch{
		Evts: evts,
	}
}

func pbToBatch(pbB *pb.Batch) prog.Batch {
	var batch prog.Batch
	for i, evtsList := range pbB.Evts {
		batch.Events = append(batch.Events, make([]prog.EvtrackEvent, 0))
		for _, evt := range evtsList.Events {
			batch.Events[i] = append(batch.Events[i], pbToEvent(evt))
		}
	}
	return batch
}

func groupToPb(group prog.Group) *pb.Group {
	var evts []*pb.EventsList = make([]*pb.EventsList, prog.EVTRACK_EVENT_TYPES)
	for i, evtList := range group.Events {
		var events []*pb.EvtrackEvent = make([]*pb.EvtrackEvent, len(evtList))
		for j, evt := range evtList {
			events[j] = eventToPb(evt)
		}
		evts[i] = &pb.EventsList{
			Events: events,
		}
	}
	return &pb.Group{
		Id: group.ID,
		NumGroups: group.NumGroups,
		Events: evts,
	}
}

func pbToProgGroup(pbGroup *pb.Group) *prog.Group {
	var group prog.Group
	for i, evtsList := range pbGroup.Events {
		group.Events = append(group.Events, make([]prog.EvtrackEvent, 0))
		for _, evt := range evtsList.Events {
			group.Events[i] = append(group.Events[i], pbToEvent(evt))
		}
	}
	group.ID = pbGroup.Id
	group.NumGroups = pbGroup.NumGroups
	return &group
}

func groupsToPb(groups []*prog.Group) *pb.ChangedGroups {
	var grps []*pb.Group = make([]*pb.Group, len(groups))
	for i, grp := range groups {
		grps[i] = groupToPb(*grp)
	}
	return &pb.ChangedGroups{
		Groups: grps,
	}
}

func pbToGroups(pbChanged *pb.ChangedGroups) []*prog.Group {
	var changed []*prog.Group = make([]*prog.Group, len(pbChanged.Groups))
	for i := range pbChanged.Groups {
		changed[i] = pbToProgGroup(pbChanged.Groups[i])
	}
	return changed
}

func load_groups(filename string) [][]prog.EvtrackEvent {
	gob.RegisterName("github.com/google/syzkaller/prog.PointerArg", &prog.PointerArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.ResultArg", &prog.ResultArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.GroupArg", &prog.GroupArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.DataArg", &prog.DataArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.ConstArg", &prog.ConstArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.UnionArg", &prog.UnionArg{})

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	dec := gob.NewDecoder(bytes.NewBuffer(content))
	var groups [][]prog.EvtrackEvent
	err = dec.Decode(&groups)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return groups
}

