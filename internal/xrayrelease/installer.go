package xrayrelease

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Relayward/relayward-sdk/contract"
)

const (
	maximumArchiveEntries      = 128
	maximumExtractedFileSize   = 256 << 20
	maximumExtractedTotalBytes = 384 << 20
	installationMetadataFile   = ".release.json"
)

var extractedFiles = map[string]os.FileMode{
	"xray":        0o500,
	"geoip.dat":   0o400,
	"geosite.dat": 0o400,
}

type Installation struct {
	Version  string
	Binary   string
	AssetDir string
}

type Installer struct {
	dataDirectory string
	source        Source
}

type installationMetadata struct {
	Version       string            `json:"version"`
	ArchiveSize   int64             `json:"archive_size"`
	ArchiveSHA256 string            `json:"archive_sha256"`
	Files         map[string]string `json:"files"`
}

func NewInstaller(dataDirectory string, source Source) *Installer {
	return &Installer{dataDirectory: dataDirectory, source: source}
}

func (installer *Installer) Ensure(ctx context.Context, version string) (Installation, error) {
	if err := contract.ValidateSemanticVersion(version); err != nil || strings.ContainsAny(version, "-+") {
		return Installation{}, errors.New("invalid Xray version")
	}
	if installer.source == nil {
		return Installation{}, errors.New("Xray release source is not configured")
	}
	versionsDirectory := filepath.Join(installer.dataDirectory, "xray", "versions")
	if err := ensurePrivateDirectory(versionsDirectory); err != nil {
		return Installation{}, err
	}
	finalDirectory := filepath.Join(versionsDirectory, version)
	if _, err := os.Lstat(finalDirectory); err == nil {
		return verifyInstallation(finalDirectory, version)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Installation{}, fmt.Errorf("inspect installed Xray version: %w", err)
	}

	asset, err := installer.source.Resolve(ctx, version)
	if err != nil {
		return Installation{}, err
	}
	if asset.Version != version {
		return Installation{}, errors.New("official Xray release source returned a different version")
	}
	stagingDirectory, err := os.MkdirTemp(versionsDirectory, ".install-")
	if err != nil {
		return Installation{}, fmt.Errorf("create Xray installation staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDirectory)
	if err := os.Chmod(stagingDirectory, 0o700); err != nil {
		return Installation{}, fmt.Errorf("protect Xray installation staging directory: %w", err)
	}
	archivePath := filepath.Join(stagingDirectory, "xray.zip")
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Installation{}, fmt.Errorf("create Xray archive: %w", err)
	}
	downloadErr := installer.source.Download(ctx, asset, archive)
	closeErr := archive.Close()
	if downloadErr != nil {
		return Installation{}, downloadErr
	}
	if closeErr != nil {
		return Installation{}, fmt.Errorf("close Xray archive: %w", closeErr)
	}
	files, err := extractRuntimeFiles(archivePath, stagingDirectory)
	if err != nil {
		return Installation{}, err
	}
	if err := os.Remove(archivePath); err != nil {
		return Installation{}, fmt.Errorf("remove verified Xray archive: %w", err)
	}
	metadata := installationMetadata{
		Version: version, ArchiveSize: asset.Size, ArchiveSHA256: asset.SHA256, Files: files,
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return Installation{}, fmt.Errorf("encode Xray installation metadata: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stagingDirectory, installationMetadataFile), append(raw, '\n'), 0o400); err != nil {
		return Installation{}, fmt.Errorf("write Xray installation metadata: %w", err)
	}
	if err := os.Chmod(stagingDirectory, 0o500); err != nil {
		return Installation{}, fmt.Errorf("protect installed Xray version: %w", err)
	}
	if err := os.Rename(stagingDirectory, finalDirectory); err != nil {
		if _, statErr := os.Stat(finalDirectory); statErr == nil {
			return verifyInstallation(finalDirectory, version)
		}
		return Installation{}, fmt.Errorf("commit installed Xray version: %w", err)
	}
	if err := syncDirectory(versionsDirectory); err != nil {
		return Installation{}, err
	}
	return verifyInstallation(finalDirectory, version)
}

func extractRuntimeFiles(archivePath, destination string) (map[string]string, error) {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open verified Xray archive: %w", err)
	}
	defer archive.Close()
	if len(archive.File) > maximumArchiveEntries {
		return nil, errors.New("Xray archive contains too many entries")
	}
	result := make(map[string]string)
	var total uint64
	for _, entry := range archive.File {
		cleaned := path.Clean(entry.Name)
		canonicalName := strings.TrimSuffix(entry.Name, "/")
		if entry.Name == "" || path.IsAbs(entry.Name) || cleaned != canonicalName || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(entry.Name, "\\") {
			return nil, errors.New("Xray archive contains an unsafe path")
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Xray archive contains a symbolic link")
		}
		mode, wanted := extractedFiles[cleaned]
		if !wanted {
			continue
		}
		if entry.FileInfo().IsDir() || !entry.Mode().IsRegular() {
			return nil, fmt.Errorf("Xray archive entry %s is not a regular file", cleaned)
		}
		if _, duplicate := result[cleaned]; duplicate {
			return nil, fmt.Errorf("Xray archive contains duplicate %s", cleaned)
		}
		if entry.UncompressedSize64 < 1 || entry.UncompressedSize64 > maximumExtractedFileSize {
			return nil, fmt.Errorf("Xray archive entry %s exceeds size limit", cleaned)
		}
		total += entry.UncompressedSize64
		if total > maximumExtractedTotalBytes {
			return nil, errors.New("Xray runtime files exceed total size limit")
		}
		digest, err := extractFile(entry, filepath.Join(destination, cleaned), mode)
		if err != nil {
			return nil, err
		}
		result[cleaned] = digest
	}
	if result["xray"] == "" {
		return nil, errors.New("Xray archive does not contain the xray executable")
	}
	return result, nil
}

func extractFile(entry *zip.File, destination string, mode os.FileMode) (string, error) {
	source, err := entry.Open()
	if err != nil {
		return "", fmt.Errorf("open Xray archive entry: %w", err)
	}
	defer source.Close()
	target, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return "", fmt.Errorf("create Xray runtime file: %w", err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(target, hash), io.LimitReader(source, int64(entry.UncompressedSize64)+1))
	closeErr := target.Close()
	if copyErr != nil {
		return "", fmt.Errorf("extract Xray runtime file: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close Xray runtime file: %w", closeErr)
	}
	if written != int64(entry.UncompressedSize64) {
		return "", errors.New("Xray runtime file size does not match archive metadata")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyInstallation(directory, version string) (Installation, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return Installation{}, fmt.Errorf("inspect installed Xray version: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Installation{}, errors.New("installed Xray version is not a private directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Installation{}, errors.New("installed Xray version directory permissions are not private")
	}
	metadataFile, err := os.Open(filepath.Join(directory, installationMetadataFile))
	if err != nil {
		return Installation{}, fmt.Errorf("open Xray installation metadata: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(metadataFile, 64<<10))
	decoder.DisallowUnknownFields()
	var metadata installationMetadata
	decodeErr := decoder.Decode(&metadata)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	closeErr := metadataFile.Close()
	if decodeErr != nil {
		return Installation{}, fmt.Errorf("decode Xray installation metadata: %w", decodeErr)
	}
	if trailingErr != io.EOF {
		return Installation{}, errors.New("Xray installation metadata contains trailing data")
	}
	if closeErr != nil {
		return Installation{}, fmt.Errorf("close Xray installation metadata: %w", closeErr)
	}
	if metadata.Version != version || metadata.ArchiveSize < 1 || !validSHA256(metadata.ArchiveSHA256) {
		return Installation{}, errors.New("installed Xray version has invalid release metadata")
	}
	if len(metadata.Files) < 1 || len(metadata.Files) > len(extractedFiles) || metadata.Files["xray"] == "" {
		return Installation{}, errors.New("installed Xray version has an invalid file inventory")
	}
	for name, expectedDigest := range metadata.Files {
		mode, allowed := extractedFiles[name]
		if !allowed || !validSHA256(expectedDigest) {
			return Installation{}, errors.New("installed Xray version has an invalid file inventory")
		}
		filePath := filepath.Join(directory, name)
		fileInfo, err := os.Lstat(filePath)
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
			return Installation{}, fmt.Errorf("installed Xray runtime file %s is invalid", name)
		}
		if name == "xray" && fileInfo.Mode().Perm()&0o100 == 0 {
			return Installation{}, errors.New("installed Xray executable is not executable")
		}
		if fileInfo.Mode().Perm() != mode {
			return Installation{}, fmt.Errorf("installed Xray runtime file %s has invalid permissions", name)
		}
		if fileInfo.Size() < 1 || fileInfo.Size() > maximumExtractedFileSize {
			return Installation{}, fmt.Errorf("installed Xray runtime file %s has an invalid size", name)
		}
		actualDigest, err := fileSHA256(filePath)
		if err != nil {
			return Installation{}, err
		}
		if actualDigest != expectedDigest {
			return Installation{}, fmt.Errorf("installed Xray runtime file %s failed integrity verification", name)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return Installation{}, fmt.Errorf("list installed Xray version: %w", err)
	}
	if len(entries) != len(metadata.Files)+1 {
		return Installation{}, errors.New("installed Xray version contains files outside its verified inventory")
	}
	for _, entry := range entries {
		if entry.Name() == installationMetadataFile {
			continue
		}
		if _, ok := metadata.Files[entry.Name()]; !ok {
			return Installation{}, errors.New("installed Xray version contains files outside its verified inventory")
		}
	}
	return Installation{Version: version, Binary: filepath.Join(directory, "xray"), AssetDir: directory}, nil
}

func fileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open installed Xray runtime file: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumExtractedFileSize+1)); err != nil {
		return "", fmt.Errorf("hash installed Xray runtime file: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func ensurePrivateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create Xray versions directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect Xray versions directory: %w", err)
	}
	return nil
}

func syncDirectory(directory string) error {
	value, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open Xray versions directory: %w", err)
	}
	defer value.Close()
	if err := value.Sync(); err != nil {
		return fmt.Errorf("sync Xray versions directory: %w", err)
	}
	return nil
}
