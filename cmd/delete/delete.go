package main

import (
	"log"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var DefaultKeyAuth = []byte("12345678")

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

	var handle tpmutil.Handle = 0

	for _, val := range vals {
		handle = val.(tpmutil.Handle)
		if err := tpm2.FlushContext(tpm, handle); err != nil {
			log.Fatalf("Error deleting key with handle %v: %v", handle, err)
		}
		log.Printf("Deleted key with handle %v", handle)
	}
}
