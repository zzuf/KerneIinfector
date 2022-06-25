package main

import (
	"fmt"
	"os"

	win32 "github.com/0xrawsec/golang-win32"
	"github.com/AllenDang/w32"
)

type Offsets struct {
	tes win32.HWND
}

func getVersionOffsets() {
	winver := w32.RegGetString(w32.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId")
	fmt.Println("[+] Windows Version %s Found!", winver)
	switch winver {
	case "1909":
	case "2004":
	}
}

func findProcessCallbackRoutine(r string) {

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
