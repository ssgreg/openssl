package openssl

import "testing"

func TestVerifyError(t *testing.T) {
	e := NewVerifyError(Ok)
	if e != nil {
		t.Error("Not VerifyError")
	}

	e = NewVerifyError(CertHasExpired)
	if _, ok := e.(*VerifyError); !ok {
		t.Error("Not VerifyError")
	}

	if len(e.Error()) == 0 {
		t.Errorf("Error() failed")
	}
}
