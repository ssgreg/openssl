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
	SHA256Size      = 32
	SHA256BlockSize = 64
)

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
