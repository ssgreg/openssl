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

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"
	"testing"
)

func testSHA2(t *testing.T, testFn func(data []byte)) {
	for i := 0; i < 100; i++ {
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}
		testFn(buf)
	}
}

func TestSHA224(t *testing.T) {
	testSHA2(t, func(data []byte) {
		expected := sha256.Sum224(data)
		got, err := SHA224(data)
		if err != nil {
			t.Fatal(err)
		}
		if expected != got {
			t.Fatalf("exp:%x got:%x", expected, got)
		}
	})
}

func TestSHA56(t *testing.T) {
	testSHA2(t, func(data []byte) {
		expected := sha256.Sum256(data)
		got, err := SHA256(data)
		if err != nil {
			t.Fatal(err)
		}
		if expected != got {
			t.Fatalf("exp:%x got:%x", expected, got)
		}
	})
}

func TestSHA384(t *testing.T) {
	testSHA2(t, func(data []byte) {
		expected := sha512.Sum384(data)
		got, err := SHA384(data)
		if err != nil {
			t.Fatal(err)
		}
		if expected != got {
			t.Fatalf("exp:%x got:%x", expected, got)
		}
	})
}

func TestSHA512(t *testing.T) {
	testSHA2(t, func(data []byte) {
		expected := sha512.Sum512(data)
		got, err := SHA512(data)
		if err != nil {
			t.Fatal(err)
		}
		if expected != got {
			t.Fatalf("exp:%x got:%x", expected, got)
		}
	})
}

func testSHA2Writer(t *testing.T, opensslHash Hash, stdlibHash hash.Hash) {
	for i := 0; i < 100; i++ {
		if err := opensslHash.Reset(); err != nil {
			t.Fatal(err)
		}
		stdlibHash.Reset()
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		if _, err := opensslHash.Write(buf); err != nil {
			t.Fatal(err)
		}
		if _, err := stdlibHash.Write(buf); err != nil {
			t.Fatal(err)
		}

		got, err := opensslHash.Sum()
		if err != nil {
			t.Fatal(err)
		}
		exp := stdlibHash.Sum(nil)
		if !bytes.Equal(got, exp) {
			t.Fatalf("exp:%x got:%x", exp, got)
		}
	}
}

func TestSHA224Writer(t *testing.T) {
	ohash, err := NewSHA224Hash()
	if err != nil {
		t.Fatal(err)
	}
	testSHA2Writer(t, ohash, sha256.New224())
}

func TestSHA256Writer(t *testing.T) {
	ohash, err := NewSHA256Hash()
	if err != nil {
		t.Fatal(err)
	}
	testSHA2Writer(t, ohash, sha256.New())
}

func TestSHA384Writer(t *testing.T) {
	ohash, err := NewSHA384Hash()
	if err != nil {
		t.Fatal(err)
	}
	testSHA2Writer(t, ohash, sha512.New384())
}

func TestSHA512Writer(t *testing.T) {
	ohash, err := NewSHA512Hash()
	if err != nil {
		t.Fatal(err)
	}
	testSHA2Writer(t, ohash, sha512.New())
}

func benchmarkSHA2(b *testing.B, length int64, fn shafunc) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(buf)
	}
}

func BenchmarkSHA224Large_openssl(b *testing.B) {
	benchmarkSHA2(b, 1024*1024, func(buf []byte) { SHA224(buf) })
}

func BenchmarkSHA224Large_stdlib(b *testing.B) {
	benchmarkSHA2(b, 1024*1024, func(buf []byte) { sha256.Sum224(buf) })
}

func BenchmarkSHA224Small_openssl(b *testing.B) {
	benchmarkSHA2(b, 1, func(buf []byte) { SHA224(buf) })
}

func BenchmarkSHA224Small_stdlib(b *testing.B) {
	benchmarkSHA2(b, 1, func(buf []byte) { sha256.Sum224(buf) })
}

func BenchmarkSHA256Large_openssl(b *testing.B) {
	benchmarkSHA2(b, 1024*1024, func(buf []byte) { SHA256(buf) })
}

func BenchmarkSHA256Large_stdlib(b *testing.B) {
	benchmarkSHA2(b, 1024*1024, func(buf []byte) { sha256.Sum256(buf) })
}

func BenchmarkSHA256Small_openssl(b *testing.B) {
	benchmarkSHA2(b, 1, func(buf []byte) { SHA256(buf) })
}

func BenchmarkSHA256Small_stdlib(b *testing.B) {
	benchmarkSHA2(b, 1, func(buf []byte) { sha256.Sum256(buf) })
}

func BenchmarkSHA384Large_openssl(b *testing.B) {
	benchmarkSHA2(b, 1024*1024, func(buf []byte) { SHA384(buf) })
}

func BenchmarkSHA384Large_stdlib(b *testing.B) {
	benchmarkSHA2(b, 1024*1024, func(buf []byte) { sha512.Sum384(buf) })
}

func BenchmarkSHA384Small_openssl(b *testing.B) {
	benchmarkSHA2(b, 1, func(buf []byte) { SHA384(buf) })
}

func BenchmarkSHA384Small_stdlib(b *testing.B) {
	benchmarkSHA2(b, 1, func(buf []byte) { sha512.Sum384(buf) })
}

func BenchmarkSHA512Large_openssl(b *testing.B) {
	benchmarkSHA2(b, 1024*1024, func(buf []byte) { SHA512(buf) })
}

func BenchmarkSHA512Large_stdlib(b *testing.B) {
	benchmarkSHA2(b, 1024*1024, func(buf []byte) { sha512.Sum512(buf) })
}

func BenchmarkSHA512Small_openssl(b *testing.B) {
	benchmarkSHA2(b, 1, func(buf []byte) { SHA512(buf) })
}

func BenchmarkSHA512Small_stdlib(b *testing.B) {
	benchmarkSHA2(b, 1, func(buf []byte) { sha512.Sum512(buf) })
}
