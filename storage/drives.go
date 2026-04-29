package storage

import (
	"fmt"
	"path/filepath"
	"strings"

	"fileline/models"
)

// BuildStoragePath creates the persisted object key/path for one uploaded file.
func BuildStoragePath(fileID, fileName string) string {
	ext := filepath.Ext(fileName)
	return fileID + ext
}

// ApplyFileDefaults normalizes missing drive/path values on legacy rows.
func ApplyFileDefaults(file *models.FileEntry) {
	if file == nil {
		return
	}
	if file.DriveID == "" {
		file.DriveID = models.LocalDriveID
	}
	if file.StoragePath == "" {
		file.StoragePath = BuildStoragePath(file.ID, file.Name)
	}
}

// NormalizeSettingsDrives guarantees a deterministic drive list with local first.
func NormalizeSettingsDrives(settings *models.AppSettings) {
	if settings == nil {
		return
	}
	settings.StorageDrives = models.NormalizeStorageDrives(settings.StorageDrives)
}

func isDriveConfigured(drive models.StorageDrive) bool {
	switch drive.Type {
	case models.StorageTypeS3:
		return strings.TrimSpace(drive.S3Endpoint) != "" &&
			strings.TrimSpace(drive.S3Bucket) != "" &&
			strings.TrimSpace(drive.S3AccessKey) != "" &&
			strings.TrimSpace(drive.S3SecretKey) != ""
	case models.StorageTypeFTP:
		return strings.TrimSpace(drive.FTPHost) != "" &&
			strings.TrimSpace(drive.FTPUsername) != "" &&
			strings.TrimSpace(drive.FTPPassword) != ""
	case models.StorageTypeSFTP:
		return strings.TrimSpace(drive.SFTPHost) != "" &&
			strings.TrimSpace(drive.SFTPUsername) != "" &&
			strings.TrimSpace(drive.SFTPPassword) != ""
	default:
		return true
	}
}

// UploadDrives returns drives that can be selected as upload targets.
func UploadDrives(settings models.AppSettings) []models.StorageDrive {
	normalized := models.NormalizeStorageDrives(settings.StorageDrives)
	drives := make([]models.StorageDrive, 0, len(normalized))
	for _, drive := range normalized {
		if drive.ID == models.LocalDriveID {
			drive.Enabled = true
			drive.Type = models.StorageTypeLocal
			if strings.TrimSpace(drive.Name) == "" {
				drive.Name = "Local Disk"
			}
			drives = append(drives, drive)
			continue
		}
		if !drive.Enabled || !isDriveConfigured(drive) {
			continue
		}
		drives = append(drives, drive)
	}
	if len(drives) == 0 {
		return []models.StorageDrive{models.DefaultLocalDrive()}
	}
	return drives
}

// ResolveUploadDrive finds a configured upload drive from the provided drive ID.
func ResolveUploadDrive(settings models.AppSettings, requestedID string) (models.StorageDrive, error) {
	available := UploadDrives(settings)
	requestedID = strings.ToLower(strings.TrimSpace(requestedID))
	if requestedID == "" {
		requestedID = models.LocalDriveID
	}
	for _, drive := range available {
		if drive.ID == requestedID {
			return drive, nil
		}
	}
	return models.StorageDrive{}, fmt.Errorf("unknown or disabled drive: %s", requestedID)
}

// DriveByID returns one configured drive by ID (including local), regardless of enabled state.
func DriveByID(settings models.AppSettings, driveID string) models.StorageDrive {
	normalized := models.NormalizeStorageDrives(settings.StorageDrives)
	driveID = strings.ToLower(strings.TrimSpace(driveID))
	for _, drive := range normalized {
		if drive.ID == driveID {
			return drive
		}
	}
	return models.DefaultLocalDrive()
}
