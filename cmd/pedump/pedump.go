package main

import (
	"fmt"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/kjk/u"

	"debug/pe"
)

/*
func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print("Must specify the filename of the PE file\n")
		return
	}
	pefile, err := pe.NewFile(args[0])
	if err != nil {
		log.Println("Ooopss looks like there was a problem")
		log.Println(err)
		return
	}
	log.Println(pefile.Filename)
	log.Println(pefile.DosHeader)
	log.Println(pefile.NTHeader)
	log.Println(pefile.FileHeader)
	log.Println(pefile.OptionalHeader)

	for key, val := range pefile.OptionalHeader.DataDirs {
		log.Println(key)
		log.Println(val)
	}

	fmt.Printf("%v\n", pefile.Sections)

	fmt.Print("\nDIRECTORY_ENTRY_IMPORT\n")
	for _, entry := range pefile.ImportDescriptors {
		for _, imp := range entry.Imports {
			var funcname string
			if len(imp.Name) == 0 {
				funcname = pe.OrdLookup(string(entry.Dll), uint64(imp.Ordinal), true)
			} else {
				funcname = string(imp.Name)
			}
			log.Println(funcname)
		}
	}

	fmt.Print("\nDIRECTORY_ENTRY_EXPORT\n")
	fmt.Print(pefile.ExportDirectory)
	for _, entry := range pefile.ExportDirectory.Exports {
		log.Println(string(entry.Name))
	}
}
*/

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print("Must specify the filename of the PE file\n")
		return
	}
	pefile, err := pe.Open(args[0])
	u.PanicIfErr(err)
	defer pefile.Close()
	spew.Dump(pefile.FileHeader)
	spew.Dump(pefile.OptionalHeader)
}
