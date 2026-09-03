package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"
	"github.com/Relayward/relayward-sdk/contract"
	"github.com/Relayward/relayward-sdk/manifest"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/pluginmeta"
)

func main() {
	flags := flag.NewFlagSet("relayward-plugin-xray-release", flag.ExitOnError)
	directory := flags.String("dist", "dist", "release artifact directory")
	version := flags.String("version", "", "semantic plugin version")
	flags.Parse(os.Args[1:])
	if flags.NArg() != 0 {
		fatal("unexpected positional argument")
	}
	if err := contract.ValidateSemanticVersion(*version); err != nil {
		fatal("invalid version: %v", err)
	}
	value := releaseManifest(*version)
	for _, artifact := range []struct {
		role manifest.ArtifactRole
		name string
	}{
		{role: manifest.ArtifactCenter, name: "relayward-plugin-xray-center-linux-amd64"},
		{role: manifest.ArtifactNode, name: "relayward-plugin-xray-node-linux-amd64"},
		{role: manifest.ArtifactUI, name: "relayward-plugin-xray-ui.tar.gz"},
	} {
		description, err := describeArtifact(filepath.Join(*directory, artifact.name), artifact.role, artifact.name)
		if err != nil {
			fatal("%v", err)
		}
		value.Artifacts = append(value.Artifacts, description)
	}
	if err := manifest.Validate(value); err != nil {
		fatal("generated manifest is invalid: %v", err)
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatal("encode manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(*directory, "relayward-plugin.json"), append(raw, '\n'), 0o644); err != nil {
		fatal("write manifest: %v", err)
	}
}

func releaseManifest(version string) manifest.Manifest {
	agentAPI := uint32(contract.AgentAPIMajor)
	uiAPI := uint32(contract.UIAPIMajor)
	return manifest.Manifest{
		APIVersion: contract.ManifestAPIVersion,
		ID:         pluginmeta.ID,
		Name:       "Xray",
		Version:    version,
		Kind:       manifest.KindRuntime,
		Requires: manifest.Requirements{
			ControlAPI: contract.ControlAPIMajor,
			AgentAPI:   &agentAPI,
			UIAPI:      &uiAPI,
		},
		Permissions: []manifest.Permission{
			{Name: centerpluginv1.PermissionAuthorizationsRead, Reason: "List node authorizations when configuring user-specific access rules."},
			{Name: centerpluginv1.PermissionPortDiagnose, Reason: "Read node listener status and test configured subscription endpoint ports."},
			{Name: centerpluginv1.PermissionNodeConfigure, Reason: "Read and publish the Xray plugin configuration for managed nodes."},
			{Name: centerpluginv1.PermissionNodeDiagnose, Reason: "Inspect node addresses and test configured Xray egress lines on demand."},
			{Name: centerpluginv1.PermissionServicesWrite, Reason: "Publish Xray services that can be bound to node authorizations."},
		},
		UI: &manifest.UIContribution{NodeDetail: &manifest.NodeDetailContribution{
			Label: manifest.LocalizedLabel{ZhCN: "Xray", En: "Xray"},
			Icon:  manifest.NavigationIconServerCog, Order: 400,
		}},
	}
}

func describeArtifact(path string, role manifest.ArtifactRole, name string) (manifest.Artifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return manifest.Artifact{}, fmt.Errorf("open %s artifact: %w", role, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return manifest.Artifact{}, fmt.Errorf("inspect %s artifact: %w", role, err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return manifest.Artifact{}, fmt.Errorf("hash %s artifact: %w", role, err)
	}
	result := manifest.Artifact{Role: role, File: name, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))}
	if role == manifest.ArtifactCenter || role == manifest.ArtifactNode {
		result.OS = "linux"
		result.Arch = "amd64"
	}
	return result, nil
}

func fatal(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
