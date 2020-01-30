package main

import "debug/pe"

type IMAGE_REL_BASED uint16
type baseRelocEntry uint16

//IMAGE_DOS_HEADER type
type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

//IMAGE_NT_HEADERS32 type
type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader32
}

//IMAGE_NT_HEADERS64 type
type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader64
}

//IMAGE_BASE_RELOCATION type
type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

//BASE_RELOCATION_ENTRY bit fields Offset uint16 :12 Type uint16 :4
type BASE_RELOCATION_ENTRY uint16

//GetOffset func
func (r *BASE_RELOCATION_ENTRY) GetOffset() (_offset uint16) {
	_offset = uint16(*r) & 0x0fff
	return
}

//SetOffset func
func (r *BASE_RELOCATION_ENTRY) SetOffset(_offset uint16) {
	*r = *r | BASE_RELOCATION_ENTRY(_offset&0x0fff)
}

//SetType func
func (r *BASE_RELOCATION_ENTRY) SetType(_type uint16) {
	*r = *r | BASE_RELOCATION_ENTRY(_type&0xf000)
}

//GetType func
func (r *BASE_RELOCATION_ENTRY) GetType() (_type uint16) {
	_type = (uint16(*r) & 0xf000) >> 12
	return
}

//m128a struct
type m128a struct {
	low  uint64
	high int64
}

//WOW64_FLOATING_SAVE_AREA struct
type WOW64_FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

//WOW64_CONTEXT struct
type WOW64_CONTEXT struct {
	ContextFlags      uint32
	Dr0               uint32
	Dr1               uint32
	Dr2               uint32
	Dr3               uint32
	Dr6               uint32
	Dr7               uint32
	FloatSave         WOW64_FLOATING_SAVE_AREA
	SegGs             uint32
	SegFs             uint32
	SegEs             uint32
	SegDs             uint32
	Edi               uint32
	Esi               uint32
	Ebx               uint32
	Edx               uint32
	Ecx               uint32
	Eax               uint32
	Ebp               uint32
	Eip               uint32
	SegCs             uint32
	EFlags            uint32
	Esp               uint32
	SegSs             uint32
	ExtendedRegisters [512]byte
}

//CONTEXT truct
type CONTEXT struct {
	p1home               uint64
	p2home               uint64
	p3home               uint64
	p4home               uint64
	p5home               uint64
	p6home               uint64
	contextflags         uint32
	mxcsr                uint32
	segcs                uint16
	segds                uint16
	seges                uint16
	segfs                uint16
	seggs                uint16
	segss                uint16
	eflags               uint32
	dr0                  uint64
	dr1                  uint64
	dr2                  uint64
	dr3                  uint64
	dr6                  uint64
	dr7                  uint64
	rax                  uint64
	rcx                  uint64
	rdx                  uint64
	rbx                  uint64
	rsp                  uint64
	rbp                  uint64
	rsi                  uint64
	rdi                  uint64
	r8                   uint64
	r9                   uint64
	r10                  uint64
	r11                  uint64
	r12                  uint64
	r13                  uint64
	r14                  uint64
	r15                  uint64
	rip                  uint64
	anon0                [512]byte
	vectorregister       [26]m128a
	vectorcontrol        uint64
	debugcontrol         uint64
	lastbranchtorip      uint64
	lastbranchfromrip    uint64
	lastexceptiontorip   uint64
	lastexceptionfromrip uint64
}
