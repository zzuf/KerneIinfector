// Code generated by 'go generate'; DO NOT EDIT.

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modpsapi    = windows.NewLazySystemDLL("psapi.dll")

	procBuildSecurityDescriptorW   = modadvapi32.NewProc("BuildSecurityDescriptorW")
	procCloseServiceHandle         = modadvapi32.NewProc("CloseServiceHandle")
	procCreateServiceW             = modadvapi32.NewProc("CreateServiceW")
	procDeleteService              = modadvapi32.NewProc("DeleteService")
	procLocalFree                  = modadvapi32.NewProc("LocalFree")
	procOpenSCManagerW             = modadvapi32.NewProc("OpenSCManagerW")
	procOpenServiceW               = modadvapi32.NewProc("OpenServiceW")
	procQueryServiceObjectSecurity = modadvapi32.NewProc("QueryServiceObjectSecurity")
	procRegGetValueW               = modadvapi32.NewProc("RegGetValueW")
	procSetEntriesInAclW           = modadvapi32.NewProc("SetEntriesInAclW")
	procSetServiceObjectSecurity   = modadvapi32.NewProc("SetServiceObjectSecurity")
	procStartServiceW              = modadvapi32.NewProc("StartServiceW")
	procCloseHandle                = modkernel32.NewProc("CloseHandle")
	procCreateFile                 = modkernel32.NewProc("CreateFile")
	procDeviceIoControl            = modkernel32.NewProc("DeviceIoControl")
	procFreeLibrary                = modkernel32.NewProc("FreeLibrary")
	procGetLastError               = modkernel32.NewProc("GetLastError")
	procGetProcAddress             = modkernel32.NewProc("GetProcAddress")
	procLoadLibraryW               = modkernel32.NewProc("LoadLibraryW")
	procEnumDeviceDrivers          = modpsapi.NewProc("EnumDeviceDrivers")
)

func BuildSecurityDescriptorW(pOwner unsafe.Pointer, pGroup unsafe.Pointer, cCountOfAccessEntries int64, pListOfAccessEntries *windows.EXPLICIT_ACCESS, cCountOfAuditEntries int64, pListOfAuditEntries *windows.EXPLICIT_ACCESS, pOldSD unsafe.Pointer, pSizeNewSD uint32, pNewSD *uintptr) (ret uint32) {
	r0, _, _ := syscall.Syscall9(procBuildSecurityDescriptorW.Addr(), 9, uintptr(pOwner), uintptr(pGroup), uintptr(cCountOfAccessEntries), uintptr(unsafe.Pointer(pListOfAccessEntries)), uintptr(cCountOfAuditEntries), uintptr(unsafe.Pointer(pListOfAuditEntries)), uintptr(pOldSD), uintptr(pSizeNewSD), uintptr(unsafe.Pointer(pNewSD)))
	ret = uint32(r0)
	return
}

func CloseServiceHandle(hSCObject uintptr) (ret bool) {
	r0, _, _ := syscall.Syscall(procCloseServiceHandle.Addr(), 1, uintptr(hSCObject), 0, 0)
	ret = r0 != 0
	return
}

func CreateServiceW(hSCManager uintptr, lpServiceName string, lpDisplayName string, dwDesiredAccess uint32, dwServiceType uint32, dwStartType uint32, dwErrorControl uint32, lpBinaryPathName string, lpLoadOrderGroup string, lpdwTagId string, lpDependencies string, lpServiceStartName string, lpPassword string) (handle uintptr, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(lpServiceName)
	if err != nil {
		return
	}
	var _p1 *uint16
	_p1, err = syscall.UTF16PtrFromString(lpDisplayName)
	if err != nil {
		return
	}
	var _p2 *uint16
	_p2, err = syscall.UTF16PtrFromString(lpBinaryPathName)
	if err != nil {
		return
	}
	var _p3 *uint16
	_p3, err = syscall.UTF16PtrFromString(lpLoadOrderGroup)
	if err != nil {
		return
	}
	var _p4 *uint16
	_p4, err = syscall.UTF16PtrFromString(lpdwTagId)
	if err != nil {
		return
	}
	var _p5 *uint16
	_p5, err = syscall.UTF16PtrFromString(lpDependencies)
	if err != nil {
		return
	}
	var _p6 *uint16
	_p6, err = syscall.UTF16PtrFromString(lpServiceStartName)
	if err != nil {
		return
	}
	var _p7 *uint16
	_p7, err = syscall.UTF16PtrFromString(lpPassword)
	if err != nil {
		return
	}
	return _CreateServiceW(hSCManager, _p0, _p1, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, _p2, _p3, _p4, _p5, _p6, _p7)
}

func _CreateServiceW(hSCManager uintptr, lpServiceName *uint16, lpDisplayName *uint16, dwDesiredAccess uint32, dwServiceType uint32, dwStartType uint32, dwErrorControl uint32, lpBinaryPathName *uint16, lpLoadOrderGroup *uint16, lpdwTagId *uint16, lpDependencies *uint16, lpServiceStartName *uint16, lpPassword *uint16) (handle uintptr, err error) {
	r0, _, e1 := syscall.Syscall15(procCreateServiceW.Addr(), 13, uintptr(hSCManager), uintptr(unsafe.Pointer(lpServiceName)), uintptr(unsafe.Pointer(lpDisplayName)), uintptr(dwDesiredAccess), uintptr(dwServiceType), uintptr(dwStartType), uintptr(dwErrorControl), uintptr(unsafe.Pointer(lpBinaryPathName)), uintptr(unsafe.Pointer(lpLoadOrderGroup)), uintptr(unsafe.Pointer(lpdwTagId)), uintptr(unsafe.Pointer(lpDependencies)), uintptr(unsafe.Pointer(lpServiceStartName)), uintptr(unsafe.Pointer(lpPassword)), 0, 0)
	handle = uintptr(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func DeleteService(hService uintptr) (ret bool) {
	r0, _, _ := syscall.Syscall(procDeleteService.Addr(), 1, uintptr(hService), 0, 0)
	ret = r0 != 0
	return
}

func LocalFree(hMem uintptr) (ret bool) {
	r0, _, _ := syscall.Syscall(procLocalFree.Addr(), 1, uintptr(hMem), 0, 0)
	ret = r0 != 0
	return
}

func OpenSCManagerW(lpMachineName string, lpDatabaseName string, dwDesiredAccess uint32) (handle uintptr, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(lpMachineName)
	if err != nil {
		return
	}
	var _p1 *uint16
	_p1, err = syscall.UTF16PtrFromString(lpDatabaseName)
	if err != nil {
		return
	}
	return _OpenSCManagerW(_p0, _p1, dwDesiredAccess)
}

func _OpenSCManagerW(lpMachineName *uint16, lpDatabaseName *uint16, dwDesiredAccess uint32) (handle uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procOpenSCManagerW.Addr(), 3, uintptr(unsafe.Pointer(lpMachineName)), uintptr(unsafe.Pointer(lpDatabaseName)), uintptr(dwDesiredAccess))
	handle = uintptr(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenServiceW(hSCManager uintptr, lpServiceName string, dwDesiredAccess uint32) (handle uintptr, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(lpServiceName)
	if err != nil {
		return
	}
	return _OpenServiceW(hSCManager, _p0, dwDesiredAccess)
}

func _OpenServiceW(hSCManager uintptr, lpServiceName *uint16, dwDesiredAccess uint32) (handle uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procOpenServiceW.Addr(), 3, uintptr(hSCManager), uintptr(unsafe.Pointer(lpServiceName)), uintptr(dwDesiredAccess))
	handle = uintptr(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func QueryServiceObjectSecurity(hService uintptr, dwSecurityInformation uint32, lpSecurityDescriptor uintptr, cbBufSize uint32, pcbBytesNeeded *uint32) (ret bool) {
	r0, _, _ := syscall.Syscall6(procQueryServiceObjectSecurity.Addr(), 5, uintptr(hService), uintptr(dwSecurityInformation), uintptr(lpSecurityDescriptor), uintptr(cbBufSize), uintptr(unsafe.Pointer(pcbBytesNeeded)), 0)
	ret = r0 != 0
	return
}

func RegGetValueW(hkey int, lpSubKey string, lpValue string, dwFlags uint32, pdwType *uint32, pvData uintptr, pcbData *uint32) (ret uint32, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(lpSubKey)
	if err != nil {
		return
	}
	var _p1 *uint16
	_p1, err = syscall.UTF16PtrFromString(lpValue)
	if err != nil {
		return
	}
	return _RegGetValueW(hkey, _p0, _p1, dwFlags, pdwType, pvData, pcbData)
}

func _RegGetValueW(hkey int, lpSubKey *uint16, lpValue *uint16, dwFlags uint32, pdwType *uint32, pvData uintptr, pcbData *uint32) (ret uint32, err error) {
	r0, _, e1 := syscall.Syscall9(procRegGetValueW.Addr(), 7, uintptr(hkey), uintptr(unsafe.Pointer(lpSubKey)), uintptr(unsafe.Pointer(lpValue)), uintptr(dwFlags), uintptr(unsafe.Pointer(pdwType)), uintptr(pvData), uintptr(unsafe.Pointer(pcbData)), 0, 0)
	ret = uint32(r0)
	if ret == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetEntriesInAclW(cCountOfExplicitEntries uint32, pListOfExplicitEntries *windows.EXPLICIT_ACCESS, OldAcl *windows.ACL, NewAcl **windows.ACL) (ret uint32) {
	r0, _, _ := syscall.Syscall6(procSetEntriesInAclW.Addr(), 4, uintptr(cCountOfExplicitEntries), uintptr(unsafe.Pointer(pListOfExplicitEntries)), uintptr(unsafe.Pointer(OldAcl)), uintptr(unsafe.Pointer(NewAcl)), 0, 0)
	ret = uint32(r0)
	return
}

func SetServiceObjectSecurity(hService uintptr, dwSecurityInformation uint32, lpSecurityDescriptor uintptr) (ret bool) {
	r0, _, _ := syscall.Syscall(procSetServiceObjectSecurity.Addr(), 3, uintptr(hService), uintptr(dwSecurityInformation), uintptr(lpSecurityDescriptor))
	ret = r0 != 0
	return
}

func StartServiceW(hService uintptr, dwNumServiceArgs uint32, lpServiceArgVectors *int16) (ret bool) {
	r0, _, _ := syscall.Syscall(procStartServiceW.Addr(), 3, uintptr(hService), uintptr(dwNumServiceArgs), uintptr(unsafe.Pointer(lpServiceArgVectors)))
	ret = r0 != 0
	return
}

func CloseHandle(hObject HANDLE) (ret bool) {
	r0, _, _ := syscall.Syscall(procCloseHandle.Addr(), 1, uintptr(hObject), 0, 0)
	ret = r0 != 0
	return
}

func CreateFile(lpFileName string, dwDesiredAccess uint32, dwShareMode uint32, lpSecurityAttributes *SECURITY_ATTRIBUTES, dwCreationDisposition uint32, dwFlagsAndAttributes uint32, hTemplateFile uintptr) (handle uintptr, err error) {
	var _p0 *byte
	_p0, err = syscall.BytePtrFromString(lpFileName)
	if err != nil {
		return
	}
	return _CreateFile(_p0, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
}

func _CreateFile(lpFileName *byte, dwDesiredAccess uint32, dwShareMode uint32, lpSecurityAttributes *SECURITY_ATTRIBUTES, dwCreationDisposition uint32, dwFlagsAndAttributes uint32, hTemplateFile uintptr) (handle uintptr, err error) {
	r0, _, e1 := syscall.Syscall9(procCreateFile.Addr(), 7, uintptr(unsafe.Pointer(lpFileName)), uintptr(dwDesiredAccess), uintptr(dwShareMode), uintptr(unsafe.Pointer(lpSecurityAttributes)), uintptr(dwCreationDisposition), uintptr(dwFlagsAndAttributes), uintptr(hTemplateFile), 0, 0)
	handle = uintptr(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func DeviceIoControl(hDevice uintptr, dwIoControlCode uint32, lpInBuffer uintptr, nInBufferSize uint32, lpOutBuffer uintptr, nOutBufferSize uint32, lpBytesReturned *uint32) (ret bool) {
	r0, _, _ := syscall.Syscall9(procDeviceIoControl.Addr(), 7, uintptr(hDevice), uintptr(dwIoControlCode), uintptr(lpInBuffer), uintptr(nInBufferSize), uintptr(lpOutBuffer), uintptr(nOutBufferSize), uintptr(unsafe.Pointer(lpBytesReturned)), 0, 0)
	ret = r0 != 0
	return
}

func FreeLibrary(hLibModule uintptr) (ret bool) {
	r0, _, _ := syscall.Syscall(procFreeLibrary.Addr(), 1, uintptr(hLibModule), 0, 0)
	ret = r0 != 0
	return
}

func GetLastError() (ret uint32) {
	r0, _, _ := syscall.Syscall(procGetLastError.Addr(), 0, 0, 0, 0)
	ret = uint32(r0)
	return
}

func GetProcAddress(hModule uintptr, lpProcName string) (address uintptr, err error) {
	var _p0 *byte
	_p0, err = syscall.BytePtrFromString(lpProcName)
	if err != nil {
		return
	}
	return _GetProcAddress(hModule, _p0)
}

func _GetProcAddress(hModule uintptr, lpProcName *byte) (address uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procGetProcAddress.Addr(), 2, uintptr(hModule), uintptr(unsafe.Pointer(lpProcName)), 0)
	address = uintptr(r0)
	if address == 0 {
		err = errnoErr(e1)
	}
	return
}

func LoadLibraryW(lpLibFileName string) (handle uintptr, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(lpLibFileName)
	if err != nil {
		return
	}
	return _LoadLibraryW(_p0)
}

func _LoadLibraryW(lpLibFileName *uint16) (handle uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procLoadLibraryW.Addr(), 1, uintptr(unsafe.Pointer(lpLibFileName)), 0, 0)
	handle = uintptr(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func EnumDeviceDrivers(lpImageBase uintptr, cb uint32, lpcbNeeded *uint32) (ret bool) {
	r0, _, _ := syscall.Syscall(procEnumDeviceDrivers.Addr(), 3, uintptr(lpImageBase), uintptr(cb), uintptr(unsafe.Pointer(lpcbNeeded)))
	ret = r0 != 0
	return
}
