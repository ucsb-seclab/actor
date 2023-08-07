// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/ifuzz"
)

const (
	// "Recommended" number of calls in programs that we try to aim at during fuzzing.
	RecommendedCalls = 20
	// "Recommended" max number of calls in programs.
	// If we receive longer programs from hub/corpus we discard them.
	MaxCalls = 40
)

type randGen struct {
	*rand.Rand
	target             *Target
	inGenerateResource bool
	recDepth           map[string]int
}

func newRand(target *Target, rs rand.Source) *randGen {
	return &randGen{
		Rand:     rand.New(rs),
		target:   target,
		recDepth: make(map[string]int),
	}
}

func (r *randGen) rand(n int) uint64 {
	return uint64(r.Intn(n))
}

func (r *randGen) randRange(begin, end uint64) uint64 {
	return begin + uint64(r.Intn(int(end-begin+1)))
}

func (r *randGen) bin() bool {
	return r.Intn(2) == 0
}

func (r *randGen) oneOf(n int) bool {
	return r.Intn(n) == 0
}

func (r *randGen) rand64() uint64 {
	v := uint64(r.Int63())
	if r.bin() {
		v |= 1 << 63
	}
	return v
}

var (
	// Some potentially interesting integers.
	specialInts = []uint64{
		0, 1, 31, 32, 63, 64, 127, 128,
		129, 255, 256, 257, 511, 512,
		1023, 1024, 1025, 2047, 2048, 4095, 4096,
		(1 << 15) - 1, (1 << 15), (1 << 15) + 1,
		(1 << 16) - 1, (1 << 16), (1 << 16) + 1,
		(1 << 31) - 1, (1 << 31), (1 << 31) + 1,
		(1 << 32) - 1, (1 << 32), (1 << 32) + 1,
		(1 << 63) - 1, (1 << 63), (1 << 63) + 1,
		(1 << 64) - 1,
	}
	// The indexes (exclusive) for the maximum specialInts values that fit in 1, 2, ... 8 bytes.
	specialIntIndex [9]int
)

func init() {
	sort.Slice(specialInts, func(i, j int) bool {
		return specialInts[i] < specialInts[j]
	})
	for i := range specialIntIndex {
		bitSize := uint64(8 * i)
		specialIntIndex[i] = sort.Search(len(specialInts), func(i int) bool {
			return specialInts[i]>>bitSize != 0
		})
	}
}

func (r *randGen) randInt64() uint64 {
	return r.randInt(64)
}

func (r *randGen) randInt(bits uint64) uint64 {
	v := r.rand64()
	switch {
	case r.nOutOf(100, 182):
		v %= 10
	case bits >= 8 && r.nOutOf(50, 82):
		v = specialInts[r.Intn(specialIntIndex[bits/8])]
	case r.nOutOf(10, 32):
		v %= 256
	case r.nOutOf(10, 22):
		v %= 4 << 10
	case r.nOutOf(10, 12):
		v %= 64 << 10
	default:
		v %= 1 << 31
	}
	switch {
	case r.nOutOf(100, 107):
	case r.nOutOf(5, 7):
		v = uint64(-int64(v))
	default:
		v <<= uint(r.Intn(int(bits)))
	}
	return truncateToBitSize(v, bits)
}

func truncateToBitSize(v, bitSize uint64) uint64 {
	if bitSize == 0 || bitSize > 64 {
		panic(fmt.Sprintf("invalid bitSize value: %d", bitSize))
	}
	return v & uint64(1<<bitSize-1)
}

func (r *randGen) randRangeInt(begin, end, bitSize, align uint64) uint64 {
	if r.oneOf(100) {
		return r.randInt(bitSize)
	}
	if align != 0 {
		if begin == 0 && int64(end) == -1 {
			// Special [0:-1] range for all possible values.
			end = uint64(1<<bitSize - 1)
		}
		endAlign := (end - begin) / align
		return begin + r.randRangeInt(0, endAlign, bitSize, 0)*align
	}
	return begin + (r.Uint64() % (end - begin + 1))
}

// biasedRand returns a random int in range [0..n),
// probability of n-1 is k times higher than probability of 0.
func (r *randGen) biasedRand(n, k int) int {
	nf, kf := float64(n), float64(k)
	rf := nf * (kf/2 + 1) * r.Float64()
	bf := (-1 + math.Sqrt(1+2*kf*rf/nf)) * nf / kf
	return int(bf)
}

func (r *randGen) randArrayLen() uint64 {
	const maxLen = 10
	// biasedRand produces: 10, 9, ..., 1, 0,
	// we want: 1, 2, ..., 9, 10, 0
	return uint64(maxLen-r.biasedRand(maxLen+1, 10)+1) % (maxLen + 1)
}

func (r *randGen) randBufLen() (n uint64) {
	switch {
	case r.nOutOf(50, 56):
		n = r.rand(256)
	case r.nOutOf(5, 6):
		n = 4 << 10
	}
	return
}

func (r *randGen) randPageCount() (n uint64) {
	switch {
	case r.nOutOf(100, 106):
		n = r.rand(4) + 1
	case r.nOutOf(5, 6):
		n = r.rand(20) + 1
	default:
		n = (r.rand(3) + 1) * r.target.NumPages / 4
	}
	return
}

// Change a flag value or generate a new one.
// If you are changing this function, run TestFlags and examine effect of results.
func (r *randGen) flags(vv []uint64, bitmask bool, oldVal uint64) uint64 {
	// Get these simpler cases out of the way first.
	// Once in a while we want to return completely random values,
	// or 0 which is frequently special.
	if r.oneOf(100) {
		return r.rand64()
	}
	if r.oneOf(50) {
		return 0
	}
	if !bitmask && oldVal != 0 && r.oneOf(100) {
		// Slightly increment/decrement the old value.
		// This is especially important during mutation when len(vv) == 1,
		// otherwise in that case we produce almost no randomness
		// (the value is always mutated to 0).
		inc := uint64(1)
		if r.bin() {
			inc = ^uint64(0)
		}
		v := oldVal + inc
		for r.bin() {
			v += inc
		}
		return v
	}
	if len(vv) == 1 {
		// This usually means that value or 0,
		// at least that's our best (and only) bet.
		if r.bin() {
			return 0
		}
		return vv[0]
	}
	if !bitmask && !r.oneOf(10) {
		// Enumeration, so just choose one of the values.
		return vv[r.rand(len(vv))]
	}
	if r.oneOf(len(vv) + 4) {
		return 0
	}
	// Flip rand bits. Do this for non-bitmask sometimes
	// because we may have detected bitmask incorrectly for complex cases
	// (e.g. part of the vlaue is bitmask and another is not).
	v := oldVal
	if v != 0 && r.oneOf(10) {
		v = 0 // Ignore the old value sometimes.
	}
	// We don't want to return 0 here, because we already given 0
	// fixed probability above (otherwise we get 0 too frequently).
	// Note: this loop can hang if all values are equal to 0. We don't generate such flags in the compiler now,
	// but it used to hang occasionally, so we keep the try < 10 logic b/c we don't have a local check for values.
	for try := 0; try < 10 && (v == 0 || r.nOutOf(2, 3)); try++ {
		flag := vv[r.rand(len(vv))]
		if r.oneOf(20) {
			// Try choosing adjacent bit values in case we forgot
			// to add all relevant flags to the descriptions.
			if r.bin() {
				flag >>= 1
			} else {
				flag <<= 1
			}
		}
		v ^= flag
	}
	return v
}

func (r *randGen) filename(s *state, typ *BufferType) string {
	fn := r.filenameImpl(s)
	if fn != "" && fn[len(fn)-1] == 0 {
		panic(fmt.Sprintf("zero-terminated filename: %q", fn))
	}
	if escapingFilename(fn) {
		panic(fmt.Sprintf("sandbox escaping file name %q, s.files are %v", fn, s.files))
	}
	if !typ.Varlen() {
		size := typ.Size()
		if uint64(len(fn)) < size {
			fn += string(make([]byte, size-uint64(len(fn))))
		}
		fn = fn[:size]
	} else if !typ.NoZ {
		fn += "\x00"
	}
	return fn
}

func escapingFilename(file string) bool {
	file = filepath.Clean(file)
	return len(file) >= 1 && file[0] == '/' ||
		len(file) >= 2 && file[0] == '.' && file[1] == '.'
}

var specialFiles = []string{"", "."}

func (r *randGen) filenameImpl(s *state) string {
	if r.oneOf(100) {
		return specialFiles[r.Intn(len(specialFiles))]
	}
	if len(s.files) == 0 || r.oneOf(10) {
		// Generate a new name.
		dir := "."
		if r.oneOf(2) && len(s.files) != 0 {
			dir = r.randFromMap(s.files)
			if dir != "" && dir[len(dir)-1] == 0 {
				dir = dir[:len(dir)-1]
			}
			if r.oneOf(10) && filepath.Clean(dir)[0] != '.' {
				dir += "/.."
			}
		}
		for i := 0; ; i++ {
			f := fmt.Sprintf("%v/file%v", dir, i)
			if !s.files[f] {
				return f
			}
		}
	}
	return r.randFromMap(s.files)
}

func (r *randGen) randFromMap(m map[string]bool) string {
	files := make([]string, 0, len(m))
	for f := range m {
		files = append(files, f)
	}
	sort.Strings(files)
	return files[r.Intn(len(files))]
}

func (r *randGen) randString(s *state, t *BufferType) []byte {
	if len(t.Values) != 0 {
		return []byte(t.Values[r.Intn(len(t.Values))])
	}
	if len(s.strings) != 0 && r.bin() {
		// Return an existing string.
		// TODO(dvyukov): make s.strings indexed by string SubKind.
		return []byte(r.randFromMap(s.strings))
	}
	punct := []byte{'!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '\\',
		'/', ':', '.', ',', '-', '\'', '[', ']', '{', '}'}
	buf := new(bytes.Buffer)
	for r.nOutOf(3, 4) {
		if r.nOutOf(10, 11) {
			buf.Write([]byte{punct[r.Intn(len(punct))]})
		} else {
			buf.Write([]byte{byte(r.Intn(256))})
		}
	}
	if r.oneOf(100) == t.NoZ {
		buf.Write([]byte{0})
	}
	return buf.Bytes()
}

func (r *randGen) allocAddr(s *state, typ Type, dir Dir, size uint64, data Arg) *PointerArg {
	return MakePointerArg(typ, dir, s.ma.alloc(r, size, data.Type().Alignment()), data)
}

func (r *randGen) allocVMA(s *state, typ Type, dir Dir, numPages uint64) *PointerArg {
	page := s.va.alloc(r, numPages)
	return MakeVmaPointerArg(typ, dir, page*r.target.PageSize, numPages*r.target.PageSize)
}

func (r *randGen) createResource(s *state, res *ResourceType, dir Dir) (Arg, []*Call) {
	if !r.inGenerateResource {
		panic("inGenerateResource is not set")
	}
	kind := res.Desc.Name
	// Find calls that produce the necessary resources.
	// TODO: reduce priority of less specialized ctors.
	metas := r.enabledCtors(s, kind)
	// We may have no resources, but still be in createResource due to ANYRES.
	if len(r.target.resourceMap) != 0 && r.oneOf(1000) {
		// Spoof resource subkind.
		var all []string
		for kind1 := range r.target.resourceMap {
			if r.target.isCompatibleResource(res.Desc.Kind[0], kind1) {
				all = append(all, kind1)
			}
		}
		if len(all) == 0 {
			panic(fmt.Sprintf("got no spoof resources for %v in %v/%v",
				kind, r.target.OS, r.target.Arch))
		}
		sort.Strings(all)
		kind1 := all[r.Intn(len(all))]
		metas1 := r.enabledCtors(s, kind1)
		if len(metas1) != 0 {
			// Don't use the resource for which we don't have any ctors.
			// It's fine per-se because below we just return nil in such case.
			// But in TestCreateResource tests we want to ensure that we don't fail
			// to create non-optional resources, and if we spoof a non-optional
			// resource with ctors with a optional resource w/o ctors, then that check will fail.
			kind, metas = kind1, metas1
		}
	}
	if len(metas) == 0 {
		// We may not have any constructors for optional input resources because we don't disable
		// syscalls based on optional inputs resources w/o ctors in TransitivelyEnabledCalls.
		return nil, nil
	}
	// Now we have a set of candidate calls that can create the necessary resource.
	// Generate one of them.
	meta := metas[r.Intn(len(metas))]
	calls := r.generateParticularCall(s, meta)
	s1 := newState(r.target, s.ct, nil, s.evState)
	s1.analyze(calls[len(calls)-1])
	// Now see if we have what we want.
	var allres []*ResultArg
	for kind1, res1 := range s1.resources {
		if r.target.isCompatibleResource(kind, kind1) {
			allres = append(allres, res1...)
		}
	}
	sort.SliceStable(allres, func(i, j int) bool {
		return allres[i].Type().Name() < allres[j].Type().Name()
	})
	if len(allres) == 0 {
		panic(fmt.Sprintf("failed to create a resource %v (%v) with %v",
			res.Desc.Kind[0], kind, meta.Name))
	}
	arg := MakeResultArg(res, dir, allres[r.Intn(len(allres))], 0)
	return arg, calls
}

func (r *randGen) enabledCtors(s *state, kind string) []*Syscall {
	var metas []*Syscall
	for _, meta := range r.target.resourceCtors[kind] {
		if s.ct.Enabled(meta.ID) {
			metas = append(metas, meta)
		}
	}
	return metas
}

func (r *randGen) generateText(kind TextKind) []byte {
	switch kind {
	case TextTarget:
		if cfg := createTargetIfuzzConfig(r.target); cfg != nil {
			return ifuzz.Generate(cfg, r.Rand)
		}
		fallthrough
	case TextArm64:
		// Just a stub, need something better.
		text := make([]byte, 50)
		for i := range text {
			text[i] = byte(r.Intn(256))
		}
		return text
	default:
		cfg := createIfuzzConfig(kind)
		return ifuzz.Generate(cfg, r.Rand)
	}
}

func (r *randGen) mutateText(kind TextKind, text []byte) []byte {
	switch kind {
	case TextTarget:
		if cfg := createTargetIfuzzConfig(r.target); cfg != nil {
			return ifuzz.Mutate(cfg, r.Rand, text)
		}
		fallthrough
	case TextArm64:
		return mutateData(r, text, 40, 60)
	default:
		cfg := createIfuzzConfig(kind)
		return ifuzz.Mutate(cfg, r.Rand, text)
	}
}

func createTargetIfuzzConfig(target *Target) *ifuzz.Config {
	cfg := &ifuzz.Config{
		Len:  10,
		Priv: false,
		Exec: true,
		MemRegions: []ifuzz.MemRegion{
			{Start: target.DataOffset, Size: target.NumPages * target.PageSize},
		},
	}
	for _, p := range target.SpecialPointers {
		cfg.MemRegions = append(cfg.MemRegions, ifuzz.MemRegion{
			Start: p & ^target.PageSize, Size: p & ^target.PageSize + target.PageSize,
		})
	}
	switch target.Arch {
	case "amd64":
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchX86
	case "386":
		cfg.Mode = ifuzz.ModeProt32
		cfg.Arch = ifuzz.ArchX86
	case "ppc64":
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchPowerPC
	default:
		return nil
	}
	return cfg
}

func createIfuzzConfig(kind TextKind) *ifuzz.Config {
	cfg := &ifuzz.Config{
		Len:  10,
		Priv: true,
		Exec: true,
		MemRegions: []ifuzz.MemRegion{
			{Start: 0 << 12, Size: 1 << 12},
			{Start: 1 << 12, Size: 1 << 12},
			{Start: 2 << 12, Size: 1 << 12},
			{Start: 3 << 12, Size: 1 << 12},
			{Start: 4 << 12, Size: 1 << 12},
			{Start: 5 << 12, Size: 1 << 12},
			{Start: 6 << 12, Size: 1 << 12},
			{Start: 7 << 12, Size: 1 << 12},
			{Start: 8 << 12, Size: 1 << 12},
			{Start: 9 << 12, Size: 1 << 12},
			{Start: 0xfec00000, Size: 0x100}, // ioapic
		},
	}
	switch kind {
	case TextX86Real:
		cfg.Mode = ifuzz.ModeReal16
		cfg.Arch = ifuzz.ArchX86
	case TextX86bit16:
		cfg.Mode = ifuzz.ModeProt16
		cfg.Arch = ifuzz.ArchX86
	case TextX86bit32:
		cfg.Mode = ifuzz.ModeProt32
		cfg.Arch = ifuzz.ArchX86
	case TextX86bit64:
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchX86
	case TextPpc64:
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchPowerPC
	default:
		panic("unknown text kind")
	}
	return cfg
}

// nOutOf returns true n out of outOf times.
func (r *randGen) nOutOf(n, outOf int) bool {
	if n <= 0 || n >= outOf {
		panic("bad probability")
	}
	v := r.Intn(outOf)
	return v < n
}

func (r *randGen) generateCalls(s *state, p *Prog, insertionPoint int, inGeneration int) ([]*Call, bool) {
	if s.evState.GetLength() < 50 || r.Intn(2) == 0 {
		return r.generateCall(s, p, insertionPoint), false
	} else {
		return r.generateCallsEv(s, p, insertionPoint, inGeneration), true
	}
}

func (r *randGen) generateCallsEv(s *state, p *Prog, insertionPoint int, inGeneration int) []*Call {
	var biasCall *Call = nil
	var biasID int = -1
	if insertionPoint > 0 {
		biasCall = p.Calls[r.Intn(insertionPoint)]
		biasID = biasCall.Meta.ID
	}
	names, args := s.evState.chooseGroup(r.Rand, biasID, inGeneration)
	if names == nil || len(names) == 0 {
		return r.generateCall(s, p, insertionPoint)
	}
	meta := r.target.SyscallMap[names[0]]
	calls := r.generateParticularCallEv(s, meta, args[0], biasCall)
	if biasCall == nil {
		biasCall = calls[len(calls)-1]
	}
	for i := 1; i < len(names); i++ {
		meta = r.target.SyscallMap[names[i]]
		calls = append(calls, r.generateParticularCallEv(s, meta, args[i], biasCall)...)
	}
	return calls
}

func (r *randGen) generateCall(s *state, p *Prog, insertionPoint int) []*Call {
	biasCall := -1
	if insertionPoint > 0 {
		// Choosing the base call is based on the insertion point of the new calls sequence.
		biasCall = p.Calls[r.Intn(insertionPoint)].Meta.ID
	}
	idx := s.ct.choose(r.Rand, biasCall)
	meta := r.target.Syscalls[idx]
	return r.generateParticularCall(s, meta)
}

func (r *randGen) generateParticularCallEv(s *state, meta *Syscall, args []Arg, biasCall *Call) (calls  []*Call) {
	if meta.Attrs.Disabled {
		panic(fmt.Sprintf("generating disabled call %v", meta.Name))
	}
	if len(meta.Args) != len(args) {
		panic(fmt.Sprintf("length of syscall fields and length of previous args don't match"))
	}
	c := &Call{
		Meta: meta,
		Ret:  MakeReturnArg(meta.Ret),
	}
	c.Args, calls = r.generateArgsEv(s, meta.Args, args, biasCall, DirIn)
	r.target.assignSizesCall(c)
	return append(calls, c)
}

func (r *randGen) generateParticularCall(s *state, meta *Syscall) (calls []*Call) {
	if meta.Attrs.Disabled {
		panic(fmt.Sprintf("generating disabled call %v", meta.Name))
	}
	c := MakeCall(meta, nil)
	c.Args, calls = r.generateArgs(s, meta.Args, DirIn)
	r.target.assignSizesCall(c)
	return append(calls, c)
}

// GenerateAllSyzProg generates a program that contains all pseudo syz_ calls for testing.
func (target *Target) GenerateAllSyzProg(rs rand.Source) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, target.DefaultChoiceTable(), nil, nil)
	handled := make(map[string]bool)
	for _, meta := range target.Syscalls {
		if !strings.HasPrefix(meta.CallName, "syz_") || handled[meta.CallName] || meta.Attrs.Disabled {
			continue
		}
		handled[meta.CallName] = true
		calls := r.generateParticularCall(s, meta)
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	if err := p.validate(); err != nil {
		panic(err)
	}
	return p
}

// DataMmapProg creates program that maps data segment.
// Also used for testing as the simplest program.
func (target *Target) DataMmapProg() *Prog {
	return &Prog{
		Target: target,
		Calls:  target.MakeDataMmap(),
	}
}

func (r *randGen) generateArgsEv(s *state, fields []Field, args []Arg, biasCall *Call, dir Dir) ([]Arg, []*Call) {
	var calls []*Call
	new_args := make([]Arg, len(fields))

	for i, field := range fields {
		arg, calls1 := r.generateArgEv(s, field.Type, args[i], biasCall, field.Dir(dir))
		if arg == nil {
			panic(fmt.Sprintf("generated arg is nil for field '%v', fields: %+v", field.Type.Name(), fields))
		}
		new_args[i] = arg
		calls = append(calls, calls1...)
	}

	return new_args, calls
}

func (r *randGen) generateArgs(s *state, fields []Field, dir Dir) ([]Arg, []*Call) {
	var calls []*Call
	args := make([]Arg, len(fields))

	// Generate all args. Size args have the default value 0 for now.
	for i, field := range fields {
		arg, calls1 := r.generateArg(s, field.Type, field.Dir(dir))
		if arg == nil {
			panic(fmt.Sprintf("generated arg is nil for field '%v', fields: %+v", field.Type.Name(), fields))
		}
		args[i] = arg
		calls = append(calls, calls1...)
	}

	return args, calls
}

func (r *randGen) generateArgEv(s *state, typ Type, prev_arg Arg, biasCall *Call, dir Dir) (Arg, []*Call) {
	if prev_arg == nil {
		// since we cannot reuse a recorded argument we have to go back to the conventional way
		r.generateArg(s, typ, dir)
	}
	switch typ.(type) {
	case *IntType, *ConstType, *FlagsType, *LenType, *ProcType, *CsumType:
		// No special resources needed, we can just use the old stuff
		constArg, ok := prev_arg.(*ConstArg)
		if !ok {
			return r.generateArg(s, typ, dir)
		}
		return MakeConstArg(typ, dir, constArg.Val), nil
	case *VmaType:
		ptrArg, ok := prev_arg.(*PointerArg)
		if !ok {
			fmt.Println(prev_arg)
			panic("type of prev_arg is wrong")
		}
		return MakeVmaPointerArg(typ, dir, ptrArg.Address, ptrArg.VmaSize), nil
	case *BufferType, *StructType, *UnionType, *PtrType, *ArrayType, *ResourceType:
		return typ.generateEv(r, s, prev_arg, biasCall, dir)
	}
	return nil, nil
}

func (a *BufferType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	if prev_arg == nil || a.TypeSize != prev_arg.Size() {
		return a.generate(r, s, dir)
	} else {
		prevDataArg, ok := prev_arg.(*DataArg)
		if !ok {
			return a.generate(r, s, dir)
		}
		if dir == DirOut {
			return MakeOutDataArg(a, dir, prevDataArg.size), nil
		} else {
			return MakeDataArg(a, dir, prevDataArg.data), nil
		}
	}
}

func (a *StructType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	if prev_arg == nil {
		return a.generate(r, s, dir)
	}
	// prev_arg should be GroupArg
	var groupArg *GroupArg
	switch prev_arg.(type) {
	case *GroupArg:
		groupArg = prev_arg.(*GroupArg)
	default:
		return a.generate(r, s, dir)
	}
	var inner []Arg
	for i := 0; i < len(a.Fields); i++ {
		var arg1 Arg
		var calls1 []*Call
		if len(groupArg.Inner) <= i {
			arg1, calls1 = r.generateArg(s, a.Fields[i].Type, dir)
		} else {
			arg1, calls1 = r.generateArgEv(s, a.Fields[i].Type, groupArg.Inner[i], biasCall, a.Fields[i].Dir(dir))
		}
		if arg1 == nil {
			panic("arg1 is nil! this should not be")
		}
		inner = append(inner, arg1)
		calls = append(calls, calls1...)
	}
	return MakeGroupArg(a, dir, inner), calls
}

func (a *ArrayType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	if prev_arg == nil {
		return a.generate(r, s, dir)
	}
	var groupArg *GroupArg
	switch prev_arg.(type) {
	case *GroupArg:
		groupArg = prev_arg.(*GroupArg)
	default:
		return a.generate(r, s, dir)
	}

	count := len(groupArg.Inner)
	var inner []Arg
	for i := 0; i < count; i++ {
		arg1, calls1 := r.generateArgEv(s, a.Elem, groupArg.Inner[i], biasCall, dir)
		if arg1 == nil {
			panic("arg1 is nil! this should not be!")
		}
		inner = append(inner, arg1)
		calls = append(calls, calls1...)
	}
	return MakeGroupArg(a, dir, inner), calls
}

func (a *UnionType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	if prev_arg == nil {
		return a.generate(r, s, dir)
	}
	var unionArg *UnionArg
	switch prev_arg.(type) {
	case *UnionArg:
		unionArg = prev_arg.(*UnionArg)
	default:
		return a.generate(r, s, dir)
	}
	if unionArg.Index >= len(a.Fields) {
		return a.generate(r, s, dir)
	}
	optType, optDir := a.Fields[unionArg.Index].Type, a.Fields[unionArg.Index].Dir(dir)
	opt, calls := r.generateArgEv(s, optType, unionArg.Option, biasCall, optDir)
	return MakeUnionArg(a, dir, opt, unionArg.Index), calls
}

func (a *PtrType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	if prev_arg == nil {
		return a.generate(r, s, dir)
	}
	var ptrArg *PointerArg
	switch prev_arg.(type) {
	case *PointerArg:
		ptrArg = prev_arg.(*PointerArg)
	default:
		return a.generate(r, s, dir)
	}

	if ptrArg.Res == nil {
		return a.generate(r, s, dir)
	}

	inner, calls := r.generateArgEv(s, a.Elem, ptrArg.Res, biasCall, a.ElemDir)
	if inner == nil {
		panic("inner is nil")
	}
	arg = r.allocAddr(s, a, dir, inner.Size(), inner)
	return arg, calls
}

func (a *ResourceType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	// first crawl biasCall for suitable resources
	// if we cannot find anything there, create them using the generateMethod for ResourceType
	if biasCall == nil {
		return a.generate(r, s, dir)
	}
	stack := make([]Arg, len(biasCall.Args))
	for i, arg1 := range biasCall.Args {
		if arg1 != nil {
			stack[i] = arg1
		}
	}
	for ; len(stack) > 0; {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch cur.Type().(type) {
		case *StructType:
			c := cur.(*GroupArg)
			for _, field := range c.Inner {
				if field == nil {
					continue
				}
				stack = append(stack, field)
			}
		case *ArrayType:
			c := cur.(*GroupArg)
			if len(c.Inner) == 0 {
				continue
			}
			if c.Inner[0] == nil {
				continue
			}
			stack = append(stack, c.Inner[0])
		case *PtrType:
			if cur.(*PointerArg).Res == nil {
				continue
			}
			stack = append(stack, cur.(*PointerArg).Res)
		case *ResourceType:
			dstRes := s.target.resourceMap[a.Desc.Name]
			srcRes := s.target.resourceMap[cur.Type().Name()]
			if dstRes == nil || srcRes == nil {
				panic("unknown resource")
			}
			if isCompatibleResourceImpl(dstRes.Kind, srcRes.Kind, true) {
				if a.TypeSize == cur.Type().Size() {
					return MakeResultArg(a, dir, cur.(*ResultArg), 0), nil
				}
			}
		}
	}
	// no suitable resource found, let's ask the existing algorithm for help
	return a.generate(r, s, dir)
}

// never used but compiler needs it
func (a *IntType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	return prev_arg, nil
}
func (a *FlagsType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	return prev_arg, nil
}
func (a *LenType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	return prev_arg, nil
}
func (a *CsumType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	return prev_arg, nil
}
func (a *ConstType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	return prev_arg, nil
}
func (a *ProcType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	return prev_arg, nil
}
func (a *VmaType) generateEv(r *randGen, s *state, prev_arg Arg, biasCall *Call, dir Dir) (arg Arg, calls []*Call) {
	return prev_arg, nil
}

func (r *randGen) generateArg(s *state, typ Type, dir Dir) (arg Arg, calls []*Call) {
	return r.generateArgImpl(s, typ, dir, false)
}

func (r *randGen) generateArgImpl(s *state, typ Type, dir Dir, ignoreSpecial bool) (arg Arg, calls []*Call) {
	if dir == DirOut {
		// No need to generate something interesting for output scalar arguments.
		// But we still need to generate the argument itself so that it can be referenced
		// in subsequent calls. For the same reason we do generate pointer/array/struct
		// output arguments (their elements can be referenced in subsequent calls).
		switch typ.(type) {
		case *IntType, *FlagsType, *ConstType, *ProcType, *VmaType, *ResourceType:
			return typ.DefaultArg(dir), nil
		}
	}

	if typ.Optional() && r.oneOf(5) {
		if res, ok := typ.(*ResourceType); ok {
			v := res.Desc.Values[r.Intn(len(res.Desc.Values))]
			return MakeResultArg(typ, dir, nil, v), nil
		}
		return typ.DefaultArg(dir), nil
	}

	// Allow infinite recursion for optional pointers.
	if pt, ok := typ.(*PtrType); ok && typ.Optional() {
		switch pt.Elem.(type) {
		case *StructType, *ArrayType, *UnionType:
			name := pt.Elem.Name()
			r.recDepth[name]++
			defer func() {
				r.recDepth[name]--
				if r.recDepth[name] == 0 {
					delete(r.recDepth, name)
				}
			}()
			if r.recDepth[name] >= 3 {
				return MakeSpecialPointerArg(typ, dir, 0), nil
			}
		}
	}

	if !ignoreSpecial && dir != DirOut {
		switch typ.(type) {
		case *StructType, *UnionType:
			if gen := r.target.SpecialTypes[typ.Name()]; gen != nil {
				return gen(&Gen{r, s}, typ, dir, nil)
			}
		}
	}

	return typ.generate(r, s, dir)
}

func (a *ResourceType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	if !r.inGenerateResource {
		// Don't allow recursion for resourceCentric/createResource.
		// That can lead to generation of huge programs and may be very slow
		// (esp. if we are generating some failing attempts in createResource already).
		r.inGenerateResource = true
		defer func() { r.inGenerateResource = false }()

		if r.oneOf(4) {
			arg, calls = r.resourceCentric(s, a, dir)
			if arg != nil {
				return
			}
		}
		if r.oneOf(3) {
			arg, calls = r.createResource(s, a, dir)
			if arg != nil {
				return
			}
		}
	}
	if r.nOutOf(9, 10) {
		arg = r.existingResource(s, a, dir)
		if arg != nil {
			return
		}
	}
	special := a.SpecialValues()
	arg = MakeResultArg(a, dir, nil, special[r.Intn(len(special))])
	return
}

func (a *BufferType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	switch a.Kind {
	case BufferBlobRand, BufferBlobRange:
		sz := r.randBufLen()
		if a.Kind == BufferBlobRange {
			sz = r.randRange(a.RangeBegin, a.RangeEnd)
		}
		if dir == DirOut {
			return MakeOutDataArg(a, dir, sz), nil
		}
		data := make([]byte, sz)
		for i := range data {
			data[i] = byte(r.Intn(256))
		}
		return MakeDataArg(a, dir, data), nil
	case BufferString:
		data := r.randString(s, a)
		if dir == DirOut {
			return MakeOutDataArg(a, dir, uint64(len(data))), nil
		}
		return MakeDataArg(a, dir, data), nil
	case BufferFilename:
		if dir == DirOut {
			var sz uint64
			switch {
			case !a.Varlen():
				sz = a.Size()
			case r.nOutOf(1, 3):
				sz = r.rand(100)
			case r.nOutOf(1, 2):
				sz = 108 // UNIX_PATH_MAX
			default:
				sz = 4096 // PATH_MAX
			}
			return MakeOutDataArg(a, dir, sz), nil
		}
		return MakeDataArg(a, dir, []byte(r.filename(s, a))), nil
	case BufferGlob:
		return MakeDataArg(a, dir, r.randString(s, a)), nil
	case BufferText:
		if dir == DirOut {
			return MakeOutDataArg(a, dir, uint64(r.Intn(100))), nil
		}
		return MakeDataArg(a, dir, r.generateText(a.Text)), nil
	default:
		panic("unknown buffer kind")
	}
}

func (a *VmaType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	npages := r.randPageCount()
	if a.RangeBegin != 0 || a.RangeEnd != 0 {
		npages = a.RangeBegin + uint64(r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
	}
	return r.allocVMA(s, a, dir, npages), nil
}

func (a *FlagsType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	return MakeConstArg(a, dir, r.flags(a.Vals, a.BitMask, 0)), nil
}

func (a *ConstType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	return MakeConstArg(a, dir, a.Val), nil
}

func (a *IntType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	bits := a.TypeBitSize()
	v := r.randInt(bits)
	switch a.Kind {
	case IntRange:
		v = r.randRangeInt(a.RangeBegin, a.RangeEnd, bits, a.Align)
	}
	return MakeConstArg(a, dir, v), nil
}

func (a *ProcType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	return MakeConstArg(a, dir, r.rand(int(a.ValuesPerProc))), nil
}

func (a *ArrayType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	var count uint64
	switch a.Kind {
	case ArrayRandLen:
		count = r.randArrayLen()
	case ArrayRangeLen:
		count = r.randRange(a.RangeBegin, a.RangeEnd)
	}
	// The resource we are trying to generate may be in the array elements, so create at least 1.
	if r.inGenerateResource && count == 0 {
		count = 1
	}
	var inner []Arg
	for i := uint64(0); i < count; i++ {
		arg1, calls1 := r.generateArg(s, a.Elem, dir)
		inner = append(inner, arg1)
		calls = append(calls, calls1...)
	}
	return MakeGroupArg(a, dir, inner), calls
}

func (a *StructType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	args, calls := r.generateArgs(s, a.Fields, dir)
	group := MakeGroupArg(a, dir, args)
	return group, calls
}

func (a *UnionType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	index := r.Intn(len(a.Fields))
	optType, optDir := a.Fields[index].Type, a.Fields[index].Dir(dir)
	opt, calls := r.generateArg(s, optType, optDir)
	return MakeUnionArg(a, dir, opt, index), calls
}

func (a *PtrType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	// The resource we are trying to generate may be in the pointer,
	// so don't try to create an empty special pointer during resource generation.
	if !r.inGenerateResource && r.oneOf(1000) {
		index := r.rand(len(r.target.SpecialPointers))
		return MakeSpecialPointerArg(a, dir, index), nil
	}
	inner, calls := r.generateArg(s, a.Elem, a.ElemDir)
	arg = r.allocAddr(s, a, dir, inner.Size(), inner)
	return arg, calls
}

func (a *LenType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	// Updated later in assignSizesCall.
	return MakeConstArg(a, dir, 0), nil
}

func (a *CsumType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	// Filled at runtime by executor.
	return MakeConstArg(a, dir, 0), nil
}

func (r *randGen) existingResource(s *state, res *ResourceType, dir Dir) Arg {
	alltypes := make([][]*ResultArg, 0, len(s.resources))
	for _, res1 := range s.resources {
		alltypes = append(alltypes, res1)
	}
	sort.Slice(alltypes, func(i, j int) bool {
		return alltypes[i][0].Type().Name() < alltypes[j][0].Type().Name()
	})
	var allres []*ResultArg
	for _, res1 := range alltypes {
		name1 := res1[0].Type().Name()
		if r.target.isCompatibleResource(res.Desc.Name, name1) ||
			r.oneOf(50) && r.target.isCompatibleResource(res.Desc.Kind[0], name1) {
			allres = append(allres, res1...)
		}
	}
	if len(allres) == 0 {
		return nil
	}
	return MakeResultArg(res, dir, allres[r.Intn(len(allres))], 0)
}

// Finds a compatible resource with the type `t` and the calls that initialize that resource.
func (r *randGen) resourceCentric(s *state, t *ResourceType, dir Dir) (arg Arg, calls []*Call) {
	var p *Prog
	var resource *ResultArg
	for idx := range r.Perm(len(s.corpus)) {
		p = s.corpus[idx].Clone()
		resources := getCompatibleResources(p, t.TypeName, r)
		if len(resources) > 0 {
			resource = resources[r.Intn(len(resources))]
			break
		}
	}

	// No compatible resource was found.
	if resource == nil {
		return nil, nil
	}

	// Set that stores the resources that appear in the same calls with the selected resource.
	relatedRes := map[*ResultArg]bool{resource: true}

	// Remove unrelated calls from the program.
	for idx := len(p.Calls) - 1; idx >= 0; idx-- {
		includeCall := false
		var newResources []*ResultArg
		ForeachArg(p.Calls[idx], func(arg Arg, _ *ArgCtx) {
			if a, ok := arg.(*ResultArg); ok {
				if a.Res != nil && !relatedRes[a.Res] {
					newResources = append(newResources, a.Res)
				}
				if relatedRes[a] || relatedRes[a.Res] {
					includeCall = true
				}
			}
		})
		if !includeCall {
			p.RemoveCall(idx)
		} else {
			for _, res := range newResources {
				relatedRes[res] = true
			}
		}
	}

	// Selects a biased random length of the returned calls (more calls could offer more
	// interesting programs). The values returned (n = len(calls): n, n-1, ..., 2.
	biasedLen := 2 + r.biasedRand(len(calls)-1, 10)

	// Removes the references that are not used anymore.
	for i := biasedLen; i < len(calls); i++ {
		p.RemoveCall(i)
	}

	return MakeResultArg(t, dir, resource, 0), p.Calls
}

func getCompatibleResources(p *Prog, resourceType string, r *randGen) (resources []*ResultArg) {
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			// Collect only initialized resources (the ones that are already used in other calls).
			a, ok := arg.(*ResultArg)
			if !ok || len(a.uses) == 0 || a.GetDir() != DirOut {
				return
			}
			if !r.target.isCompatibleResource(resourceType, a.Type().Name()) {
				return
			}
			resources = append(resources, a)
		})
	}
	return resources
}
