package main

import "fmt"

func main() {
	payloadPath := `test.exe`
	targetPath := `C:\Windows\SysWOW64\notepad.exe`

	//Test run_pe
	//RunPE(payloadPath, targetPath)

	//Test load_pe_module1
	var payloadImageSize uint64
	loadedPE := LoadPEModule1(payloadPath, &payloadImageSize, false, false)
	fmt.Printf("Loaded_PE size in GO: %d\n", payloadImageSize)
	fmt.Printf("Loaded_PE ptr in GO: %X\n", loadedPE)

	//Test get_nt_hdr_architecture
	payloadArch := GetNTHdrArch(loadedPE)
	fmt.Printf("Paylod_arch in GO: %#x\n", payloadArch)

	//Test is64bit
	is64bit := Is64Bit(loadedPE)
	fmt.Println("Is64Bit in GO: ", is64bit)

	//Test is_target_compatible
	isTargComp := IsTargetCompatible(loadedPE, payloadImageSize, targetPath)
	fmt.Println("Is Target Compatible in GO: ", isTargComp)

	//Test create_suspended_process

	//Test _run_pe
}
