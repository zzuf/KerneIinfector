package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

func dumpProcess(processName string, outputFilePath string) {
	name, err := syscall.UTF16PtrFromString(outputFilePath)
	if err != nil {
		panic(err)
	}
	outFile, err := windows.CreateFile(name, windows.GENERIC_ALL, 0, nil, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		panic(err)
	}
	snapShot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		panic(err)
	}
	var processEntry windows.ProcessEntry32

	if windows.Process32First(snapShot, &processEntry) != nil {
		panic(err)
	}
	var tmpProcessName string
	var targetPID uint32
	for tmpProcessName != processName {
		windows.Process32Next(snapShot, &processEntry)
		tmpProcessName = syscall.UTF16ToString([]uint16(processEntry.ExeFile[:]))
		targetPID = processEntry.ProcessID
	}

	fmt.Println("Target PID : %s - %d\n", processName, targetPID)

	targetHandle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, targetPID)
	if err != nil {
		panic(err)
	}

}
