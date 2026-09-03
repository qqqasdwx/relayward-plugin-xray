package main

import (
	"slices"
	"testing"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"
)

func TestReleaseManifestPermissionsAreCanonical(t *testing.T) {
	t.Parallel()
	value := releaseManifest("0.0.0-dev")
	names := make([]string, len(value.Permissions))
	for index, permission := range value.Permissions {
		names[index] = permission.Name
	}
	want := []string{
		centerpluginv1.PermissionAuthorizationsRead,
		centerpluginv1.PermissionPortDiagnose,
		centerpluginv1.PermissionNodeConfigure,
		centerpluginv1.PermissionNodeDiagnose,
		centerpluginv1.PermissionServicesWrite,
	}
	if !slices.Equal(names, want) {
		t.Fatalf("permissions = %v, want %v", names, want)
	}
}
