package bootconfig

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	c := Config{Hostname: "h", IP: "10.0.0.2", Prefix: 24, Gateway: "10.0.0.1", MTU: 1450, DNS: []string{"10.0.0.10"}, Options: []string{"ndots:5"}, KubeNamespace: "sandbox"}
	img, err := EncodeConfig(c)
	if err != nil || len(img) != ConfigDiskSize {
		t.Fatalf("encode: %d %v", len(img), err)
	}
	got, err := DecodeConfig(img)
	if err != nil || got.IP != c.IP || got.Prefix != 24 || got.Options[0] != "ndots:5" || got.KubeNamespace != c.KubeNamespace {
		t.Fatalf("decode: %+v %v", got, err)
	}
}

func TestBootConfigContainsOnlyNamespaceMetadata(t *testing.T) {
	image, err := EncodeConfig(Config{KubeNamespace: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	if data := bytes.TrimRight(image, "\x00"); string(data) != `{"kubeNamespace":"sandbox"}` {
		t.Fatalf("boot metadata = %s", data)
	}
	data, err := json.Marshal(Config{})
	if err != nil || string(data) != "{}" {
		t.Fatalf("disabled boot metadata = %s, %v", data, err)
	}
}
