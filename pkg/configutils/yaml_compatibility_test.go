package configutils_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/configutils"
	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	yaml "go.yaml.in/yaml/v3"
	legacyyaml "gopkg.in/yaml.v3"
)

// Config files written with the maintained YAML module must remain readable by
// TeaGo, which still decodes configuration using the original v3 module path.
func TestYAMLNodeConfigLegacyInteroperability(t *testing.T) {
	fixture := []byte(`id: 9007199254740993
nodeId: "00042"
secret: "example: # quoted value"
name: "边缘节点"
isOn: true
maxCPU: 4
allowedIPs: ["2001:db8::1", "192.0.2.1"]
apiNodeAddrs:
  - protocol: https
    host: api.example.test
    portRange: "8001-8003"
servers:
  - id: 42
    clusterId: 7
    userId: 11
    isOn: true
    name: &domain "yes.example.test"
    serverNames:
      - name: *domain
`)
	var expected nodeconfigs.NodeConfig
	if err := legacyyaml.Unmarshal(fixture, &expected); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(file, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	var actual nodeconfigs.NodeConfig
	if err := configutils.UnmarshalYamlFile(file, &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("maintained YAML changed the decoded node configuration")
	}
	if actual.Id != 9007199254740993 || actual.NodeId != "00042" ||
		len(actual.Servers) != 1 || actual.Servers[0].ServerNames[0].Name != "yes.example.test" ||
		actual.APINodeAddrs[0].Protocol != serverconfigs.ProtocolHTTPS {
		t.Fatal("configuration scalar, alias or nested fields were lost")
	}
	encoded, err := yaml.Marshal(&actual)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip nodeconfigs.NodeConfig
	if err := legacyyaml.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	// Both v3 writers serialize some nil slices as empty sequences; compare
	// against the legacy writer's round trip instead of requiring nil identity.
	legacyEncoded, err := legacyyaml.Marshal(&expected)
	if err != nil {
		t.Fatal(err)
	}
	var legacyRoundtrip nodeconfigs.NodeConfig
	if err := legacyyaml.Unmarshal(legacyEncoded, &legacyRoundtrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundtrip, legacyRoundtrip) {
		t.Fatal("maintained YAML output is incompatible with the legacy decoder")
	}
}
