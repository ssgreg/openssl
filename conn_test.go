package openssl

import "testing"

func TestGetVerifyError(t *testing.T) {
	if GetVerifyError(Ok) != nil {
		t.Error("GetVerifyError(Ok) returns not nil")
	}

	if GetVerifyError(CertHasExpired) == nil {
		t.Error("GetVerifyError(CertHasExpired) returns  nil")

	}
}

func TestVerifyError(t *testing.T) {
	e := NewVerifyError(Ok)
	if _, ok := e.(*VerifyError); !ok {
		t.Error("Not VerifyError")
	}

	if e.Error() != "no error" {
		t.Errorf("Error() failed, actual: %+v", e.Error())
	}

	e = NewVerifyError(CertHasExpired)
	if e.Error() == "no error" || len(e.Error()) == 0 {
		t.Errorf("Error() failed, actual: %+v", e.Error())
	}
}
