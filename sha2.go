// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

// #include "shim.h"
import "C"

const (
	SHA224Size      = 28
	SHA224BlockSize = 64

	SHA256Size      = 32
	SHA256BlockSize = 64

	SHA384Size      = 48
	SHA384BlockSize = 128

	SHA512Size      = 64
	SHA512BlockSize = 128
)

type SHA224Hash struct {
	*internalHash
}

func NewSHA224Hash() (*SHA224Hash, error) {
	return NewSHA224HashWithEngine(nil)
}

func NewSHA224HashWithEngine(e *Engine) (*SHA224Hash, error) {
	h, err := newInternalHash(e, NID_sha224, SHA224Size, SHA224BlockSize)
	if err != nil {
		return nil, err
	}
	return &SHA224Hash{h}, nil
}

func SHA224(data []byte) (result [SHA224Size]byte, err error) {
	hash, err := NewSHA224Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()

	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	sum, err := hash.Sum()
	if err != nil {
		return result, err
	}
	copy(result[:], sum[:SHA224Size])

	return
}

type SHA256Hash struct {
	*internalHash
}

func NewSHA256Hash() (*SHA256Hash, error) {
	return NewSHA256HashWithEngine(nil)
}

func NewSHA256HashWithEngine(e *Engine) (*SHA256Hash, error) {
	h, err := newInternalHash(e, NID_sha256, SHA256Size, SHA256BlockSize)
	if err != nil {
		return nil, err
	}
	return &SHA256Hash{h}, nil
}

func SHA256(data []byte) (result [SHA256Size]byte, err error) {
	hash, err := NewSHA256Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()

	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	sum, err := hash.Sum()
	if err != nil {
		return result, err
	}
	copy(result[:], sum[:SHA256Size])

	return
}

type SHA384Hash struct {
	*internalHash
}

func NewSHA384Hash() (*SHA384Hash, error) {
	return NewSHA384HashWithEngine(nil)
}

func NewSHA384HashWithEngine(e *Engine) (*SHA384Hash, error) {
	h, err := newInternalHash(e, NID_sha384, SHA384Size, SHA384BlockSize)
	if err != nil {
		return nil, err
	}
	return &SHA384Hash{h}, nil
}

func SHA384(data []byte) (result [SHA384Size]byte, err error) {
	hash, err := NewSHA384Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()

	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	sum, err := hash.Sum()
	if err != nil {
		return result, err
	}
	copy(result[:], sum[:SHA384Size])

	return
}

type SHA512Hash struct {
	*internalHash
}

func NewSHA512Hash() (*SHA512Hash, error) {
	return NewSHA512HashWithEngine(nil)
}

func NewSHA512HashWithEngine(e *Engine) (*SHA512Hash, error) {
	h, err := newInternalHash(e, NID_sha512, SHA512Size, SHA512BlockSize)
	if err != nil {
		return nil, err
	}
	return &SHA512Hash{h}, nil
}

func SHA512(data []byte) (result [SHA512Size]byte, err error) {
	hash, err := NewSHA512Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}

	sum, err := hash.Sum()
	if err != nil {
		return result, err
	}
	copy(result[:], sum[:SHA512Size])

	return
}
