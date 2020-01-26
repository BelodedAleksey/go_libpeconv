package main

/*
#include <string.h>
#include <stdlib.h>
*/
import "C"
import (
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
	if relocate && !HasRelocations(dllRawData) {
		// ...enforce loading the PE image at its default base (so that it will need no relocations)
		desiredBase = gGetImageBase(dllRawData)
	}
	// load a virtual image of the PE file at the desired_base address (random if desired_base is NULL):
	mappedDll := PERawToVirtual(dllRawData, rSize, vSize, executable, desiredBase)
	if mappedDll != 0 {
		//if the image was loaded at its default base, relocate_module will return always true (because relocating is already done)
		if relocate && !RelocateModule(mappedDll, *vSize, mappedDll, 0) {
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