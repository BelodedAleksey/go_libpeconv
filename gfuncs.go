package main

/*
#include <string.h>
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
func VirtualAlloc(lpAddress uintptr, dwSize uint64, flAllocationType uint32, flProtect uint32) (addr uintptr, e error) {
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

//gLoadPEModule1 func
func gLoadPEModule1(fileName string, vSize *uint64, executable, relocate bool) uintptr {
	var rSize uint64
	dllRawData := gLoadFile(fileName, &rSize)
	if dllRawData == 0 {
		log.Println("Cannot load the file: ", fileName)
		return 0
	}
	mappedDll := gLoadPEModule2(dllRawData, rSize, vSize, executable, relocate)
	FreePEBuffer(dllRawData, 0)
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
		if !ValidatePtr(
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
		if !ValidatePtr(
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

//gRelocateModule func
func gRelocateModule(
	modulePtr uintptr, moduleSize uint64, newBase, oldBase uintptr) bool {
	if modulePtr == 0 {
		return false
	}
	if oldBase == 0 {
		oldBase = gGetImageBase(modulePtr)
	}
	log.Println("New Base: ", newBase)
	log.Println("Old Base: ", oldBase)
	if newBase == oldBase {
		log.Println("Nothing to relocate! oldBase is the same as the newBase!")
		return true //nothing to relocate
	}
	if ApplyRelocations(modulePtr, moduleSize, newBase, oldBase) {
		return true
	}
	log.Println("Could not relocate the module!")
	return false
}

//AllocPEBuffer func
func AllocPEBuffer(bufferSize uint64, protect uint32, desiredBase uintptr) uintptr {
	return AllocAligned(bufferSize, protect, uint64(desiredBase))
}

//SectionsRawToVirtual func
func SectionsRawToVirtual(
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

	var fileHdr *pe.FileHeader
	var hdrSize uint32
	var secptr uintptr
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(payloadNTHdr))
		fileHdr = &(payloadNTHdr64.FileHeader)
		hdrSize = payloadNTHdr64.OptionalHeader.SizeOfHeaders
		secptr = uintptr(unsafe.Pointer(&payloadNTHdr64.OptionalHeader)) + uintptr(fileHdr.SizeOfOptionalHeader)
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(unsafe.Pointer(payloadNTHdr))
		fileHdr = &(payloadNTHdr32.FileHeader)
		hdrSize = payloadNTHdr32.OptionalHeader.SizeOfHeaders
		secptr = uintptr(unsafe.Pointer(&payloadNTHdr32.OptionalHeader)) + uintptr(fileHdr.SizeOfOptionalHeader)
	}

	var firstRaw uint32
	//copy all the sections, one by one:
	//var rawEnd uint64
	var i uint16
	for i = 0; i < fileHdr.NumberOfSections; i++ {
		nextSec := (*pe.SectionHeader)(unsafe.Pointer(secptr + uintptr(IMAGE_SIZEOF_SECTION_HEADER*i)))
		if !ValidatePtr(
			payload,
			destBufferSize,
			uintptr(unsafe.Pointer(nextSec)),
			IMAGE_SIZEOF_SECTION_HEADER,
		) {
			return false
		}
		if nextSec.Offset == 0 || nextSec.Size == 0 {
			continue //skipping empty
		}
		sectionMapped := destBuffer + uintptr(nextSec.VirtualAddress)
		sectionRawPtr := payload + uintptr(nextSec.Offset)
		secSize := nextSec.Size
		//rawEnd = uint64(nextSec.Size + nextSec.Offset)

		if uint64(nextSec.VirtualAddress+secSize) > destBufferSize {
			log.Println("[!] Virtual section size is out ouf bounds: ", secSize)
			if destBufferSize > uint64(nextSec.VirtualAddress) {
				secSize = uint32(destBufferSize) - nextSec.VirtualAddress
			} else {
				secSize = 0
			}
			log.Printf("[!] Truncated to maximal size: %d, buffer size: %d", secSize, destBufferSize)
		}

		if uint64(nextSec.VirtualAddress) >= destBufferSize && secSize != 0 {
			log.Println("[-] VirtualAddress of section is out ouf bounds: ", nextSec.VirtualAddress)
			return false
		}
		if uint64(nextSec.Offset+secSize) > destBufferSize {
			log.Println("[-] Raw section size is out ouf bounds: ", secSize)
			return false
		}
		// validate source:
		if !ValidatePtr(payload, payloadSize, sectionRawPtr, uint64(secSize)) {
			log.Printf("[-] Section %d:  out ouf bounds, skipping... \n", i)
			continue
		}
		// validate destination:
		if !ValidatePtr(destBuffer, destBufferSize, sectionMapped, uint64(secSize)) {
			log.Printf("[-] Section %d:  out ouf bounds, skipping... \n", i)
			continue
		}
		mem.Memcpy(
			unsafe.Pointer(sectionMapped), unsafe.Pointer(sectionRawPtr), int(secSize))
		if firstRaw == 0 || nextSec.Offset < firstRaw {
			firstRaw = nextSec.Offset
		}
	}

	//copy payload's headers:
	if hdrSize == 0 {
		hdrSize = firstRaw
		log.Println("hdrsSize not filled, using calculated size: ", hdrSize)
	}
	if !ValidatePtr(payload, destBufferSize, payload, uint64(hdrSize)) {
		return false
	}
	mem.Memcpy(
		unsafe.Pointer(destBuffer), unsafe.Pointer(payload), int(hdrSize))
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

	if !SectionsRawToVirtual(payload, inSize, localCopyAddress, uint64(payloadImageSize)) {
		log.Println("Could not copy PE file")
		return 0
	}
	*outSize = uint64(payloadImageSize)
	return localCopyAddress
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
	mappedDll := PERawToVirtual(dllRawData, rSize, vSize, executable, desiredBase)
	if mappedDll != 0 {
		//if the image was loaded at its default base, relocate_module will return always true (because relocating is already done)
		if relocate && !gRelocateModule(mappedDll, *vSize, mappedDll, 0) {
			// relocating was required, but it failed - thus, the full PE image is useless
			log.Println("Could not relocate the module!")
			FreePEBuffer(mappedDll, *vSize)
			mappedDll = 0
		}
	} else {
		log.Println("Could not allocate memory at the desired base!")
	}
	return mappedDll
}
