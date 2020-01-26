package main

import "C"
import (
	"log"
	"syscall"
	"unsafe"
)

//RunPE func
func RunPE(payloadPath, targetPath string) uintptr {
	ret, _, err := procRunPE.Call(
		uintptr(unsafe.Pointer(C.CString(payloadPath))),
		uintptr(unsafe.Pointer(C.CString(targetPath))),
	)
	if ret == 0 {
		log.Println("Error run_pe: ", err.Error())
	}
	return ret
}

//LoadPEModule1 func
func LoadPEModule1(fileName string, vSize *uint64, executable, relocate bool) uintptr {
	var exFlag, relocFlag int
	if executable {
		exFlag = 1
	}
	if relocate {
		relocFlag = 1
	}
	ret, _, err := procLoadPEModule1.Call(
		uintptr(unsafe.Pointer(C.CString(fileName))),
		uintptr(unsafe.Pointer(vSize)),
		uintptr(exFlag),
		uintptr(relocFlag),
	)
	if ret == 0 {
		log.Println("Error load_pe_module1: ", err.Error())
	}
	return ret
}

//GetNTHdrArch func
func GetNTHdrArch(peBuffer uintptr) uintptr {
	ret, _, err := procGetNTHdrArch.Call(
		peBuffer,
	)
	if ret == 0 {
		log.Println("Error get_nt_hdr_architecture: ", err.Error())
	}
	return ret
}

//Is64Bit func
func Is64Bit(peBuffer uintptr) bool {
	ret, _, _ := procIs64Bit.Call(
		peBuffer,
	)
	return ret != 0
}

//IsTargetCompatible func
func IsTargetCompatible(payloadBuf uintptr, payloadSize uint64, targetPath string) bool {
	ret, _, _ := procIsTargetCompatible.Call(
		payloadBuf,
		uintptr(payloadSize),
		uintptr(unsafe.Pointer(C.CString(targetPath))),
	)
	return ret != 0
}

//CreateSuspendedProcess func
func CreateSuspendedProcess(path string, pi *syscall.ProcessInformation) bool {
	ret, _, err := procCreateSuspendedProcess.Call(
		uintptr(unsafe.Pointer(C.CString(path))),
		uintptr(unsafe.Pointer(pi)),
	)
	if ret == 0 {
		log.Println("Error create_suspended_process: ", err.Error())
	}
	return ret != 0
}

//RunPE2 func
func RunPE2(
	loadedPE uintptr, payloadImageSize uint64, pi *syscall.ProcessInformation, is32Bit bool,
) bool {
	var is32Flag int
	if is32Bit {
		is32Flag = 1
	}
	ret, _, err := procRunPE2.Call(
		uintptr(loadedPE),
		uintptr(payloadImageSize),
		uintptr(unsafe.Pointer(pi)),
		uintptr(is32Flag),
	)
	if ret == 0 {
		log.Println("Error _run_pe: ", err.Error())
	}
	return ret != 0
}

//FreePEBuffer func
func FreePEBuffer(buffer uintptr, bufferSize uint64) bool {
	ret, _, err := procFreePEBuffer.Call(
		uintptr(buffer),
		uintptr(bufferSize),
	)
	if ret == 0 {
		log.Println("Error free_pe_buffer: ", err.Error())
	}
	return ret != 0
}

//LoadPEModule2 func
func LoadPEModule2(dllRawData uintptr, rSize uint64, vSize *uint64, executable, relocate bool) uintptr {
	var exFlag, relocFlag int
	if executable {
		exFlag = 1
	}
	if relocate {
		relocFlag = 1
	}
	ret, _, err := procLoadPEModule2.Call(
		dllRawData,
		uintptr(rSize),
		uintptr(unsafe.Pointer(vSize)),
		uintptr(exFlag),
		uintptr(relocFlag),
	)
	if ret == 0 {
		log.Println("Error load_pe_module2: ", err.Error())
	}
	return ret
}

//LoadFile func
func LoadFile(fileName string, readSize *uint64) uintptr {
	ret, _, err := procLoadFile.Call(
		uintptr(unsafe.Pointer(C.CString(fileName))),
		uintptr(unsafe.Pointer(readSize)),
	)
	if ret == 0 {
		log.Println("Error load_file: ", err.Error())
	}
	return ret
}
