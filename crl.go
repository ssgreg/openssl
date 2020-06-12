package openssl

// #include "shim.h"
import "C"

import (
	"errors"
	"io/ioutil"
	"time"
	"unsafe"
)

type CRL struct {
	x *C.X509_CRL
}

func NewCrl(data []byte) (*CRL, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&data[0]), C.int(len(data)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}

	defer C.BIO_free(bio)

	crl_file := C.d2i_X509_CRL_bio(bio, nil)
	if crl_file == nil {
		return nil, errors.New("failed to decode CRL file")
	}

	return &CRL{x: crl_file}, nil
}

const (
	asn1TimeFormat = "Jan _2 15:04:05 2006 GMT"
)

func (c *CRL) GetNextUpdateTime() (time.Time, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	defer C.BIO_free(bio)
	t := C.X_X509_CRL_get_nextUpdate(c.x)
	if int(C.ASN1_TIME_print(bio, t)) != 1 {
		return time.Time{}, errors.New("failed to convert crl next time")
	}

	data, err := ioutil.ReadAll(asAnyBio(bio))
	if err != nil {
		return time.Time{}, errors.New("failed to read time from bio")
	}

	return time.Parse(asn1TimeFormat, string(data))
}

func (c *CRL) Free() {
	C.X509_CRL_free(c.x)
}

func VerifyCRL(crl *CRL, store *CertificateStoreCtx) bool {
	issuer := C.X_get_issuer(store.ctx)
	if issuer == nil {
		return true
	}

	ikey := C.X509_get_pubkey(issuer)
	if ikey == nil {
		return false
	}
	defer C.EVP_PKEY_free(ikey)

	if int(C.X509_CRL_verify(crl.x, ikey)) != 1 {
		return false
	}

	return true
}
