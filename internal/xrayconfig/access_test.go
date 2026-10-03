package xrayconfig

import (
	"encoding/json"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"testing"
)

func TestAccessCollectionDoesNotFallBackToConsole(t *testing.T) {
	value, err := config.NewConfiguration("26.7.28", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, disabled := range []bool{true, false} {
		value.DisableAccessLog = disabled
		raw, err := Render(value)
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Log struct {
				Access string `json:"access"`
			} `json:"log"`
		}
		if err = json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		want := "access.log"
		if disabled {
			want = "none"
		}
		if c.Log.Access != want {
			t.Fatalf("access output %q, want %q", c.Log.Access, want)
		}
	}
}
