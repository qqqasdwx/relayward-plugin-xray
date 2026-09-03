package xrayrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResolveAndDownload(t *testing.T) {
	t.Parallel()
	payload := []byte("official archive")
	digest := sha256.Sum256(payload)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v26.3.27":
			response.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(response, `{"tag_name":"v26.3.27","draft":false,"prerelease":true,"assets":[{"name":"%s","size":%d,"digest":"sha256:%s","browser_download_url":"%s/download/v26.3.27/%s"}]}`,
				assetName, len(payload), hex.EncodeToString(digest[:]), server.URL, assetName)
		case "/download/v26.3.27/" + assetName:
			response.Write(payload)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client := &Client{httpClient: server.Client(), apiBase: server.URL + "/api", assetBase: server.URL + "/download"}
	asset, err := client.Resolve(context.Background(), "26.3.27")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	var downloaded bytes.Buffer
	if err := client.Download(context.Background(), asset, &downloaded); err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	if !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatalf("downloaded = %q", downloaded.Bytes())
	}
}

func TestListVersionsReturnsOnlyInstallablePublishedReleases(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/releases" || request.URL.Query().Get("per_page") != "100" || request.URL.Query().Get("page") != "1" {
			http.NotFound(response, request)
			return
		}
		fmt.Fprintf(response, `[
			{"tag_name":"v26.8.1","draft":false,"prerelease":false,"assets":[{"name":"%s","size":12,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","browser_download_url":"%s/download/v26.8.1/%s"}]},
			{"tag_name":"v26.8.0","draft":false,"prerelease":true,"assets":[{"name":"%s","size":12,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","browser_download_url":"%s/download/v26.8.0/%s"}]},
			{"tag_name":"v26.7.9","draft":true,"assets":[]},
			{"tag_name":"not-semver","draft":false,"assets":[]},
			{"tag_name":"v26.7.8","draft":false,"assets":[]}
		]`, assetName, server.URL, assetName, assetName, server.URL, assetName)
	}))
	defer server.Close()
	client := &Client{
		httpClient: server.Client(), releasesBase: server.URL + "/releases",
		assetBase: server.URL + "/download",
	}
	versions, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].Version != "26.8.1" || versions[0].Prerelease ||
		versions[1].Version != "26.8.0" || !versions[1].Prerelease {
		t.Fatalf("ListVersions() = %+v", versions)
	}
}

func TestListVersionsAcceptsLargeOfficialReleasePage(t *testing.T) {
	t.Parallel()
	padding := strings.Repeat("x", (8<<20)+1)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(response, `[{"tag_name":"v26.8.1","draft":false,"padding":"%s","assets":[{"name":"%s","size":12,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","browser_download_url":"%s/download/v26.8.1/%s"}]}]`,
			padding, assetName, server.URL, assetName)
	}))
	defer server.Close()
	client := &Client{
		httpClient: server.Client(), releasesBase: server.URL,
		assetBase: server.URL + "/download",
	}
	versions, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].Version != "26.8.1" {
		t.Fatalf("ListVersions() = %+v", versions)
	}
}

func TestResolveRejectsUntrustedReleaseMetadata(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"draft":     `{"tag_name":"v26.3.27","draft":true,"assets":[]}`,
		"wrong URL": `{"tag_name":"v26.3.27","assets":[{"name":"Xray-linux-64.zip","size":12,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","browser_download_url":"https://example.com/Xray-linux-64.zip"}]}`,
		"no digest": `{"tag_name":"v26.3.27","assets":[{"name":"Xray-linux-64.zip","size":12,"browser_download_url":"https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip"}]}`,
	}
	for name, body := range tests {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Write([]byte(body))
			}))
			defer server.Close()
			client := &Client{httpClient: server.Client(), apiBase: server.URL, assetBase: defaultAssetBase}
			if _, err := client.Resolve(context.Background(), "26.3.27"); err == nil {
				t.Fatal("Resolve() unexpectedly succeeded")
			}
		})
	}
}

func TestDownloadRejectsDigestMismatch(t *testing.T) {
	t.Parallel()
	payload := []byte("tampered")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Write(payload)
	}))
	defer server.Close()
	client := &Client{httpClient: server.Client(), assetBase: server.URL}
	asset := Asset{
		Version: "26.3.27", URL: server.URL + "/v26.3.27/" + assetName,
		Size: int64(len(payload)), SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := client.Download(context.Background(), asset, &bytes.Buffer{}); err == nil {
		t.Fatal("Download() unexpectedly succeeded")
	}
}

func TestDownloadUsesDedicatedAssetTimeout(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	client := &Client{httpClient: server.Client(), assetBase: server.URL, downloadTimeout: 20 * time.Millisecond}
	payload := []byte("x")
	digest := sha256.Sum256(payload)
	asset := Asset{
		Version: "26.3.27", URL: server.URL + "/v26.3.27/" + assetName,
		Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
	}
	started := time.Now()
	if err := client.Download(context.Background(), asset, &bytes.Buffer{}); err == nil {
		t.Fatal("Download() unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Download() elapsed = %s", elapsed)
	}
}
