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
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modpsapi    = windows.NewLazySystemDLL("psapi.dll")

	procDeviceIoControl   = modkernel32.NewProc("DeviceIoControl")
	procFreeLibrary       = modkernel32.NewProc("FreeLibrary")
	procGetProcAddress    = modkernel32.NewProc("GetProcAddress")
	procLoadLibraryW      = modkernel32.NewProc("LoadLibraryW")
	procEnumDeviceDrivers = modpsapi.NewProc("EnumDeviceDrivers")
)

func DeviceIoControl(hDevice uintptr, dwIoControlCode uint32, lpInBuffer uintptr, nInBufferSize uint32, lpOutBuffer uintptr, nOutBufferSize uint32, lpBytesReturned *uint32) (flag bool) {
	r0, _, _ := syscall.Syscall9(procDeviceIoControl.Addr(), 7, uintptr(hDevice), uintptr(dwIoControlCode), uintptr(lpInBuffer), uintptr(nInBufferSize), uintptr(lpOutBuffer), uintptr(nOutBufferSize), uintptr(unsafe.Pointer(lpBytesReturned)), 0, 0)
	flag = r0 != 0
	return
}

func FreeLibrary(hLibModule uintptr) (flag bool) {
	r0, _, _ := syscall.Syscall(procFreeLibrary.Addr(), 1, uintptr(hLibModule), 0, 0)
	flag = r0 != 0
	return
}

func GetProcAddress(hModule uintptr, lpProcName string) (address uintptr) {
	var _p0 *byte
	_p0, _ = syscall.BytePtrFromString(lpProcName)
	return _GetProcAddress(hModule, _p0)
}

func _GetProcAddress(hModule uintptr, lpProcName *byte) (address uintptr) {
	r0, _, _ := syscall.Syscall(procGetProcAddress.Addr(), 2, uintptr(hModule), uintptr(unsafe.Pointer(lpProcName)), 0)
	address = uintptr(r0)
	return
}

func LoadLibraryW(lpLibFileName string) (handle uintptr) {
	var _p0 *uint16
	_p0, _ = syscall.UTF16PtrFromString(lpLibFileName)
	return _LoadLibraryW(_p0)
}

func _LoadLibraryW(lpLibFileName *uint16) (handle uintptr) {
	r0, _, _ := syscall.Syscall(procLoadLibraryW.Addr(), 1, uintptr(unsafe.Pointer(lpLibFileName)), 0, 0)
	handle = uintptr(r0)
	return
}

func EnumDeviceDrivers(lpImageBase uintptr, cb uint32, lpcbNeeded *uint32) (flag bool) {
	r0, _, _ := syscall.Syscall(procEnumDeviceDrivers.Addr(), 3, uintptr(lpImageBase), uintptr(cb), uintptr(unsafe.Pointer(lpcbNeeded)))
	flag = r0 != 0
	return
}
