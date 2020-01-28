package main

import "syscall"

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetFileSize           = modkernel32.NewProc("GetFileSize")
	procIsBadReadPtr          = modkernel32.NewProc("IsBadReadPtr")
	procVirtualAlloc          = modkernel32.NewProc("VirtualAlloc")
	procVirtualFree           = modkernel32.NewProc("VirtualFree")
	procResumeThread          = modkernel32.NewProc("ResumeThread")
	procVirtualAllocEx        = modkernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory    = modkernel32.NewProc("WriteProcessMemory")
	procWow64GetThreadContext = modkernel32.NewProc("Wow64GetThreadContext")
	procWow64SetThreadContext = modkernel32.NewProc("Wow64SetThreadContext")
	procGetThreadContext      = modkernel32.NewProc("GetThreadContext")
	procSetThreadContext      = modkernel32.NewProc("SetThreadContext")
)
