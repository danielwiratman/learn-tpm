package main

import (
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
)

func main() {
	tpm, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		panic(err)
	}
	defer tpm.Close()

	type tpmData struct {
		capa  tpm2.Capability
		count uint32
		props uint32
		typ   any
	}

	data := tpmData{
		capa:  tpm2.CapabilityHandles,
		count: 10,
		props: uint32(tpm2.HandleTypeTransient) << 24,
	}

	vals, _, err := tpm2.GetCapability(tpm, data.capa, data.count, data.props)
	if err != nil {
		panic(err)
	}

	for _, val := range vals {
		fmt.Printf("%+v\n", val)
	}
}
