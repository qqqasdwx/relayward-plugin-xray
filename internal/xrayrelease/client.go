// Package xrayrelease resolves and verifies official Xray release artifacts.
package xrayrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Relayward/relayward-sdk/contract"
)

const (
	assetName              = "Xray-linux-64.zip"
	defaultAPIBase         = "https://api.github.com/repos/XTLS/Xray-core/releases/tags"
	defaultReleasesBase    = "https://api.github.com/repos/XTLS/Xray-core/releases"
	defaultAssetBase       = "https://github.com/XTLS/Xray-core/releases/download"
	metadataRequestTimeout = 15 * time.Second
	assetDownloadTimeout   = 5 * time.Minute
	maximumMetadataSize    = 1 << 20
	maximumReleaseListSize = 16 << 20
	MaximumArchiveSize     = 128 << 20
	maximumReleasePages    = 10
)

type Asset struct {
	Version string
	URL     string
	Size    int64
	SHA256  string
}

type Version struct {
	Version    string `json:"version"`
	Prerelease bool   `json:"prerelease"`
}

type Source interface {
	Resolve(context.Context, string) (Asset, error)
	Download(context.Context, Asset, io.Writer) error
}

type Client struct {
	httpClient      *http.Client
	apiBase         string
	releasesBase    string
	assetBase       string
	metadataTimeout time.Duration
	downloadTimeout time.Duration
}

func NewClient() *Client {
	return &Client{
		httpClient:      &http.Client{},
		apiBase:         defaultAPIBase,
		releasesBase:    defaultReleasesBase,
		assetBase:       defaultAssetBase,
		metadataTimeout: metadataRequestTimeout,
		downloadTimeout: assetDownloadTimeout,
	}
}

func (client *Client) ListVersions(ctx context.Context) ([]Version, error) {
	requestContext, cancel := context.WithTimeout(ctx, effectiveTimeout(client.metadataTimeout, metadataRequestTimeout))
	defer cancel()
	base := strings.TrimRight(client.releasesBase, "/")
	if base == "" {
		base = defaultReleasesBase
	}
	versions := make([]Version, 0, 100)
	for page := 1; page <= maximumReleasePages; page++ {
		endpoint := base + "?per_page=100&page=" + strconv.Itoa(page)
		request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("create Xray release list request: %w", err)
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("User-Agent", "relayward-plugin-xray")
		response, err := client.httpClient.Do(request)
		if err != nil {
			return nil, fmt.Errorf("query official Xray releases: %w", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumReleaseListSize+1))
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("query official Xray releases: unexpected HTTP status %d", response.StatusCode)
		}
		if readErr != nil || closeErr != nil {
			return nil, errors.New("read official Xray releases")
		}
		if len(raw) > maximumReleaseListSize {
			return nil, errors.New("official Xray release list exceeds size limit")
		}
		var releases []struct {
			TagName    string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
			Assets     []struct {
				Name               string `json:"name"`
				Size               int64  `json:"size"`
				Digest             string `json:"digest"`
				BrowserDownloadURL string `json:"browser_download_url"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &releases); err != nil {
			return nil, fmt.Errorf("decode official Xray releases: %w", err)
		}
		for _, release := range releases {
			version, ok := strings.CutPrefix(release.TagName, "v")
			if !ok || release.Draft || contract.ValidateSemanticVersion(version) != nil || strings.ContainsAny(version, "-+") {
				continue
			}
			for _, candidate := range release.Assets {
				digest, digestOK := strings.CutPrefix(candidate.Digest, "sha256:")
				asset := Asset{Version: version, URL: candidate.BrowserDownloadURL, Size: candidate.Size, SHA256: digest}
				if candidate.Name == assetName && digestOK && client.validateAsset(asset) == nil {
					versions = append(versions, Version{Version: version, Prerelease: release.Prerelease})
					break
				}
			}
		}
		if len(releases) < 100 {
			return versions, nil
		}
	}
	return nil, errors.New("official Xray release list exceeds page limit")
}

func (client *Client) Resolve(ctx context.Context, version string) (Asset, error) {
	requestContext, cancel := context.WithTimeout(ctx, effectiveTimeout(client.metadataTimeout, metadataRequestTimeout))
	defer cancel()
	endpoint := strings.TrimRight(client.apiBase, "/") + "/v" + url.PathEscape(version)
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return Asset{}, fmt.Errorf("create Xray release request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "relayward-plugin-xray")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Asset{}, fmt.Errorf("query official Xray release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Asset{}, fmt.Errorf("query official Xray release: unexpected HTTP status %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumMetadataSize+1))
	if err != nil {
		return Asset{}, fmt.Errorf("read official Xray release: %w", err)
	}
	if len(raw) > maximumMetadataSize {
		return Asset{}, errors.New("official Xray release metadata exceeds size limit")
	}
	var release struct {
		TagName string `json:"tag_name"`
		Draft   bool   `json:"draft"`
		Assets  []struct {
			Name               string `json:"name"`
			Size               int64  `json:"size"`
			Digest             string `json:"digest"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &release); err != nil {
		return Asset{}, fmt.Errorf("decode official Xray release: %w", err)
	}
	if release.TagName != "v"+version || release.Draft {
		return Asset{}, errors.New("requested Xray version is not a published release")
	}
	var result Asset
	found := 0
	for _, candidate := range release.Assets {
		if candidate.Name != assetName {
			continue
		}
		found++
		digest, ok := strings.CutPrefix(candidate.Digest, "sha256:")
		result = Asset{Version: version, URL: candidate.BrowserDownloadURL, Size: candidate.Size, SHA256: digest}
		if !ok || !validSHA256(digest) {
			return Asset{}, errors.New("official Xray release asset has no valid SHA-256 digest")
		}
	}
	if found != 1 {
		return Asset{}, fmt.Errorf("official Xray release contains %d matching Linux AMD64 assets", found)
	}
	if err := client.validateAsset(result); err != nil {
		return Asset{}, err
	}
	return result, nil
}

func (client *Client) Download(ctx context.Context, asset Asset, destination io.Writer) error {
	if err := client.validateAsset(asset); err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, effectiveTimeout(client.downloadTimeout, assetDownloadTimeout))
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, asset.URL, nil)
	if err != nil {
		return fmt.Errorf("create Xray asset request: %w", err)
	}
	request.Header.Set("User-Agent", "relayward-plugin-xray")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("download official Xray asset: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download official Xray asset: unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != asset.Size {
		return errors.New("official Xray asset Content-Length does not match release metadata")
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(response.Body, asset.Size+1))
	if err != nil {
		return fmt.Errorf("download official Xray asset: %w", err)
	}
	if written != asset.Size {
		return errors.New("official Xray asset size does not match release metadata")
	}
	if hex.EncodeToString(hash.Sum(nil)) != asset.SHA256 {
		return errors.New("official Xray asset SHA-256 does not match release metadata")
	}
	return nil
}

func effectiveTimeout(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func (client *Client) validateAsset(asset Asset) error {
	if asset.Size < 1 || asset.Size > MaximumArchiveSize {
		return fmt.Errorf("official Xray asset size must be between 1 and %d bytes", MaximumArchiveSize)
	}
	if !validSHA256(asset.SHA256) {
		return errors.New("official Xray asset has an invalid SHA-256 digest")
	}
	expected := strings.TrimRight(client.assetBase, "/") + "/v" + asset.Version + "/" + assetName
	if asset.URL != expected {
		return errors.New("official Xray asset has an unexpected download URL")
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
