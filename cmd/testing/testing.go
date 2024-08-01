package main

import (
	"encoding/gob"
	"io"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type TPM struct {
	seed         string
	keyAuthPass  string
	pcrSelection tpm2.PCRSelection

	tpmRwc       io.ReadWriteCloser
	parentHandle tpmutil.Handle
	kv           map[int][]byte // 32 bytes long
	kvPath       string
	fileLock     sync.RWMutex

	privateBlob []byte
	publicBlob  []byte
	iv          []byte
}

func NewTPM(seed string, keyAuthPass string, pcrSelection tpm2.PCRSelection, kvPath string) *TPM {
	return &TPM{
		seed:         seed,
		keyAuthPass:  keyAuthPass,
		pcrSelection: pcrSelection,
		kvPath:       kvPath,
		iv:           make([]byte, 16),
	}
}

func (me *TPM) Init() error {
	log.Printf("Init")

	tpm, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		return err
	}

	me.tpmRwc = tpm

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
		return err
	}

	log.Printf("length of vals: %d", len(vals))

	var handle tpmutil.Handle
	for _, val := range vals {
		handle = val.(tpmutil.Handle)
		log.Printf("Handle value: %d", handle)
	}

	if handle == 0 {
		log.Printf("tpm first time initialized")
		var err error
		handle, _, err = tpm2.CreatePrimary(
			tpm,
			tpm2.HandleOwner,
			me.pcrSelection,
			"",
			me.keyAuthPass,
			tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin,
				RSAParameters: &tpm2.RSAParams{
					Symmetric: &tpm2.SymScheme{
						Alg:     tpm2.AlgAES,
						KeyBits: 128,
						Mode:    tpm2.AlgCFB,
					},
					KeyBits: 2048,
				},
			})
		if err != nil {
			return err
		}
	} else {
		log.Printf("using existing handle: %d", handle)
	}

	me.parentHandle = handle

	pv, pb, _, _, _, err := tpm2.CreateKey(
		me.tpmRwc,
		handle,
		me.pcrSelection,
		me.keyAuthPass,
		me.keyAuthPass,
		tpm2.Public{
			Type:       tpm2.AlgSymCipher,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagDecrypt | tpm2.FlagSign | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin,
			SymCipherParameters: &tpm2.SymCipherParams{
				Symmetric: &tpm2.SymScheme{
					Alg:     tpm2.AlgAES,
					KeyBits: 128,
					Mode:    tpm2.AlgCFB,
				},
			},
		},
	)
	if err != nil {
		return err
	}

	me.privateBlob = pv
	me.publicBlob = pb

	return nil
}

func (me *TPM) Close() error {
	return me.tpmRwc.Close()
}

func (me *TPM) NewConn() (tpmutil.Handle, error) {
	handle, _, err := tpm2.Load(me.tpmRwc, me.parentHandle, me.keyAuthPass, me.publicBlob, me.privateBlob)
	return handle, err
}

func (me *TPM) CloseConn(handle tpmutil.Handle) error {
	return tpm2.FlushContext(me.tpmRwc, handle)
}

var (
	DefaultSeed         = "DEFAULTSEED"
	DefaultPCRSelection = tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{7},
	}
	DefaultKeyAuth = "\x01\x02\x03\x04"
	DefaultKvPath  = "kv.gob"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <get|create|delete> <dbOid>", os.Args[0])
	}

	tpmObj := NewTPM(DefaultSeed, DefaultKeyAuth, DefaultPCRSelection, DefaultKvPath)
	if err := tpmObj.Init(); err != nil {
		log.Fatalf("Init failed: %s", err)
	}
	defer tpmObj.Close()

	newHandle, err := tpmObj.NewConn()
	if err != nil {
		log.Fatalf("NewConn failed: %s", err)
	}
	defer tpmObj.CloseConn(newHandle)

	dbOidInt, _ := strconv.Atoi(os.Args[2])
	dbOid := uint32(dbOidInt)
	switch os.Args[1] {
	case "get":
		res, status, err := tpmObj.GetKey(dbOid, newHandle)
		if err != nil {
			log.Fatalf("GetKey failed: %s", err)
		}
		_ = res
		log.Printf("Status: %d", status)
	case "create":
		status, err := tpmObj.CreateKey(dbOid, newHandle)
		if err != nil {
			log.Fatalf("CreateKey failed: %s", err)
		}
		log.Printf("Status: %d", status)
	case "delete":
		status, err := tpmObj.DeleteKey(dbOid, newHandle)
		if err != nil {
			log.Fatalf("DeleteKey failed: %s", err)
		}
		log.Printf("Status: %d", status)
	}
}

func (me *TPM) GetKey(dbOid uint32, handle tpmutil.Handle) ([]byte, byte, error) {
	log.Printf("GetKey dbOid: %d", dbOid)

	kvKeys, err := me.fetchKv()
	if err != nil {
		return nil, 0, err
	}

	kvKey := kvKeys[int(dbOid)]

	log.Printf("handle: %v", handle)
	log.Printf("iv: %v", me.iv)
	log.Printf("kvKey: %v", kvKey)

	decrypted, err := tpm2.DecryptSymmetric(me.tpmRwc, me.keyAuthPass, handle, me.iv, kvKey)
	if err != nil {
		return nil, 0, err
	}

	log.Printf("decrypted: %s", string(decrypted))

	return decrypted, 1, nil
}

func (me *TPM) CreateKey(dbOid uint32, handle tpmutil.Handle) (byte, error) {
	log.Printf("CreateKey dbOid: %d", dbOid)

	// bytesToEncrypt := []byte(string(strconv.Itoa(int(dbOid)) + "|" + me.seed))
	bytesToEncrypt := []byte("SecretCodeFromGolangServer32Bytes")

	log.Printf("handle: %v", handle)
	log.Printf("iv: %v", me.iv)
	log.Printf("bytesToEncrypt: %s", string(bytesToEncrypt))

	kvKey, err := tpm2.EncryptSymmetric(me.tpmRwc, me.keyAuthPass, handle, me.iv, bytesToEncrypt)
	if err != nil {
		return 0, err
	}

	log.Printf("kvKey: %v", kvKey)

	if err := me.updateKv(int(dbOid), kvKey); err != nil {
		return 0, err
	}

	return 0, nil
}

func (me *TPM) DeleteKey(dbOid uint32, handle tpmutil.Handle) (byte, error) {
	log.Printf("DeleteKey dbOid: %d", dbOid)

	data, err := me.fetchKv()
	if err != nil {
		return 0, err
	}

	delete(data, int(dbOid))

	if err := me.writeKv(data); err != nil {
		return 0, err
	}

	return 0, nil
}

func (me *TPM) updateKv(oid int, newData []byte) error {
	data, err := me.fetchKv()
	if err != nil && err != io.EOF {
		return err
	}
	if data == nil {
		data = make(map[int][]byte)
	}
	data[oid] = newData
	if err := me.writeKv(data); err != nil {
		return err
	}
	return nil
}

func (me *TPM) fetchKv() (map[int][]byte, error) {
	me.fileLock.RLock()
	defer me.fileLock.RUnlock()

	file, err := os.OpenFile(me.kvPath, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	var res map[int][]byte
	if err := gob.NewDecoder(file).Decode(&res); err != nil {
		return nil, err
	}
	return res, nil
}

func (me *TPM) writeKv(newData map[int][]byte) error {
	me.fileLock.Lock()
	defer me.fileLock.Unlock()

	file, err := os.OpenFile(me.kvPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(file).Encode(newData); err != nil {
		return err
	}
	return nil
}
