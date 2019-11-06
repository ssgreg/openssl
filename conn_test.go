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
