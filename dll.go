package main

import "syscall"

var (
	peconv = syscall.MustLoadDLL("run_pe.dll")

	//bool peconv::run_pe(char *payloadPath, char *targetPath)
	procRunPE = peconv.MustFindProc("_ZN6peconv6run_peEPcS0_")
	//BYTE *peconv::load_pe_module(const char *filename, OUT size_t &v_size, bool executable, bool relocate)
	procLoadPEModule1 = peconv.MustFindProc("_ZN6peconv14load_pe_moduleEPKcRybb")
	//BYTE *peconv::load_pe_module(BYTE *dllRawData, size_t r_size, OUT size_t &v_size, bool executable, bool relocate)
	procLoadPEModule2 = peconv.MustFindProc("_ZN6peconv14load_pe_moduleEPhyRybb")
	//WORD peconv::get_nt_hdr_architecture(IN const BYTE *pe_buffer)
	procGetNTHdrArch = peconv.MustFindProc("_ZN6peconv23get_nt_hdr_architectureEPKh")
	//bool peconv::is64bit(IN const BYTE *pe_buffer)
	procIs64Bit = peconv.MustFindProc("_ZN6peconv7is64bitEPKh")
	//bool create_suspended_process(IN LPSTR path, OUT PROCESS_INFORMATION &pi)
	procCreateSuspendedProcess = peconv.MustFindProc("_Z24create_suspended_processPcR20_PROCESS_INFORMATION")
	//bool _run_pe(BYTE *loaded_pe, size_t payloadImageSize, PROCESS_INFORMATION &pi, bool is32bit)
	procRunPE2 = peconv.MustFindProc("_Z7_run_pePhyR20_PROCESS_INFORMATIONb")
	//peconv::ALIGNED_BUF peconv::load_file(IN const char *filename, OUT size_t &read_size)
	procLoadFile = peconv.MustFindProc("_ZN6peconv9load_fileEPKcRy")
	//bool peconv::free_pe_buffer(peconv::ALIGNED_BUF buffer, size_t buffer_size)
	procFreePEBuffer = peconv.MustFindProc("_ZN6peconv14free_pe_bufferEPhy")
	//bool peconv::free_aligned(peconv::ALIGNED_BUF buffer, size_t buffer_size)

	//bool is_target_compatibile(BYTE *payload_buf, size_t payload_size, char *targetPath)
	procIsTargetCompatible = peconv.MustFindProc("_Z21is_target_compatibilePhyPc")
	//WORD peconv::get_subsystem(IN const BYTE* payload)
	procGetSubSystem = peconv.MustFindProc("_ZN6peconv13get_subsystemEPKh")
	//BYTE* peconv::get_nt_hdrs(IN const BYTE *pe_buffer, IN OPTIONAL size_t buffer_size)
	procGetNTHdrs = peconv.MustFindProc("_ZN6peconv11get_nt_hdrsEPKhy")
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetFileSize  = modkernel32.NewProc("GetFileSize")
	procIsBadReadPtr = modkernel32.NewProc("IsBadReadPtr")
	procVirtualAlloc = modkernel32.NewProc("VirtualAlloc")
)
