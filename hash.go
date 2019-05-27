package openssl

// #include "shim.h"
import "C"

import (
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

type Hash interface {
	io.Writer

	Reset() error
	Sum() ([]byte, error)
	Size() int
	BlockSize() int
}

type internalHash struct {
	ctx       *C.EVP_MD_CTX
	engine    *Engine
	digest    *Digest
	name      string
	size      int
	blockSize int
}

func newInternalHash(engine *Engine, nid NID, size int, blockSize int) (*internalHash, error) {
	name, err := Nid2ShortName(nid)
	if err != nil {
		return nil, err
	}

	digest, err := GetDigestByName(name)
	if err != nil {
		return nil, err
	}

	ctx := C.X_EVP_MD_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("openssl: %s: unable to allocate ctx", name)
	}

	result := &internalHash{
		ctx:       ctx,
		engine:    engine,
		digest:    digest,
		name:      name,
		size:      size,
		blockSize: blockSize,
	}
	runtime.SetFinalizer(result, func(h *internalHash) { h.Close() })
	if err := result.Reset(); err != nil {
		return nil, err
	}
	return result, nil
}

func (h *internalHash) Close() {
	if h.ctx != nil {
		C.X_EVP_MD_CTX_free(h.ctx)
		h.ctx = nil
	}
}

func (h *internalHash) Reset() error {
	if 1 != C.X_EVP_DigestInit_ex(h.ctx, h.digest.ptr, engineRef(h.engine)) {
		return fmt.Errorf("openssl: %s: cannot init digest ctx", h.name)
	}
	return nil
}

func (h *internalHash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.X_EVP_DigestUpdate(h.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, fmt.Errorf("openssl: %s: cannot update digest", h.name)
	}
	return len(p), nil
}

func (h *internalHash) Sum() ([]byte, error) {
	result := make([]byte, h.Size())
	if 1 != C.X_EVP_DigestFinal_ex(h.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, fmt.Errorf("openssl: %s: cannot finalize ctx", h.name)
	}
	return result, h.Reset()
}

func (h *internalHash) Size() int {
	return h.size
}

func (h *internalHash) BlockSize() int {
	return h.blockSize
}
