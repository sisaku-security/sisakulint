package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/core/chain"
)

func TestValidateResultHasChainRecords(t *testing.T) {
	var r ValidateResult
	r.ChainRecords = []chain.SinkRecord{{JobID: "build"}}
	if len(r.ChainRecords) != 1 {
		t.Fatal("ChainRecords field missing or wrong type")
	}
}
