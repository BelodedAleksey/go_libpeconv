package help

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

//HasRelocations func
func HasRelocations(peBuffer uintptr) bool {
	ret, _, _ := procHasRelocations.Call(
		peBuffer,
	)
	return ret != 0
}

//GetImageBase func
func GetImageBase(peBuffer uintptr) uintptr {
	ret, _, err := procGetImageBase.Call(
		peBuffer,
	)
	if ret == 0 {
		log.Println("Error get_image_base: ", err.Error())
	}
	return ret
}

//PERawToVirtual func
func PERawToVirtual(
	payload uintptr, inSize uint64, outSize *uint64, executable bool, desiredBase uintptr,
) uintptr {
	var exFlag int
	if executable {
		exFlag = 1
	}
	ret, _, err := procPERawToVirtual.Call(
		payload,
		uintptr(inSize),
		uintptr(unsafe.Pointer(outSize)),
		uintptr(exFlag),
		desiredBase,
	)
	if ret == 0 {
		log.Println("Error pe_raw_to_virtual: ", err.Error())
	}
	return ret
}

//RelocateModule func
func RelocateModule(
	modulePtr uintptr, moduleSize uint64, newBase, oldBase uintptr,
) bool {
	ret, _, err := procRelocateModule.Call(
		modulePtr,
		uintptr(moduleSize),
		newBase,
		oldBase,
	)
	if ret == 0 {
		log.Println("Error relocate_module: ", err.Error())
	}
	return ret != 0
}

//ValidatePtr func
func ValidatePtr(
	bufferBgn uintptr, bufferSize uint64, fieldBgn uintptr, fieldSize uint64,
) bool {
	ret, _, err := procValidatePtr.Call(
		bufferBgn,
		uintptr(bufferSize),
		fieldBgn,
		uintptr(fieldSize),
	)
	if ret == 0 {
		log.Println("Error validate_ptr: ", err.Error())
	}
	return ret != 0
}

//ApplyRelocations func
func ApplyRelocations(
	modulePtr uintptr, moduleSize uint64, newBase, oldBase uintptr) bool {
	ret, _, err := procApplyRelocations.Call(
		modulePtr,
		uintptr(moduleSize),
		newBase,
		oldBase,
	)
	if ret == 0 {
		log.Println("Error apply_relocations: ", err.Error())
	}
	return ret != 0
}

//SectionsRawToVirtual func
func SectionsRawToVirtual(
	payload uintptr, payloadSize uint64, destBuffer uintptr, destBufferSize uint64,
) bool {
	ret, _, err := procSectionsRawToVirtual.Call(
		payload,
		uintptr(payloadSize),
		destBuffer,
		uintptr(destBufferSize),
	)
	if ret == 0 {
		log.Println("Error sections_raw_to_virtual: ", err.Error())
	}
	return ret != 0
}

//RedirectToPayload func
func RedirectToPayload(
	loadedPE uintptr, loadBase uintptr, pi *syscall.ProcessInformation, is32bit bool,
) bool {
	var bitFlag int
	if is32bit {
		bitFlag = 1
	}
	ret, _, err := procRedirectToPayload.Call(
		loadedPE,
		loadBase,
		uintptr(unsafe.Pointer(pi)),
		uintptr(bitFlag),
	)
	if ret == 0 {
		log.Println("Error redirect_to_payload: ", err.Error())
	}
	return ret != 0
}

//GetRemotePebAddr func
func GetRemotePebAddr(pi *syscall.ProcessInformation, is32bit bool) uintptr {
	var bitFlag int
	if is32bit {
		bitFlag = 1
	}
	ret, _, err := procGetRemotePebAddr.Call(
		uintptr(unsafe.Pointer(pi)),
		uintptr(bitFlag),
	)
	if ret == 0 {
		log.Println("Error get_remote_peb_addr: ", err.Error())
	}
	return ret
}

//UpdateRemoteEntryPoint func
func UpdateRemoteEntryPoint(
	pi *syscall.ProcessInformation, entryPointVA uintptr, is32bit bool,
) bool {
	var bitFlag int
	if is32bit {
		bitFlag = 1
	}
	ret, _, err := procUpdateRemoteEntryPoint.Call(
		uintptr(unsafe.Pointer(pi)),
		entryPointVA,
		uintptr(bitFlag),
	)
	if ret == 0 {
		log.Println("Error update_remote_entry_point: ", err.Error())
	}
	return ret != 0
}

//GetEntryPointRVA func
func GetEntryPointRVA(peBuffer uintptr) uintptr {
	ret, _, err := procGetEntryPointRVA.Call(peBuffer)
	if ret == 0 {
		log.Println("Error get_entry_point_rva: ", err.Error())
	}
	return ret
}

//ProcessRelocBlock func
func ProcessRelocBlock(
	block *BASE_RELOCATION_ENTRY,
	entriesNum uint64,
	page uint32,
	modulePtr uintptr,
	moduleSize uint64,
	is64bit bool,
	oldBase uintptr,
	newBase uintptr,
) bool {
	var bitFlag int
	if is64bit {
		bitFlag = 1
	}

	ret, _, err := procProcessRelocBlock.Call(
		uintptr(unsafe.Pointer(block)),
		uintptr(entriesNum),
		uintptr(page),
		modulePtr,
		uintptr(moduleSize),
		uintptr(bitFlag),
		oldBase,
		newBase,
	)

	if ret == 0 {
		log.Println("Error process_reloc_block: ", err.Error())
	}
	return ret != 0
}
