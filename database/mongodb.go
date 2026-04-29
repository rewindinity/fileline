package database

import (
	"context"
	"encoding/json"
	"fileline/models"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

// MongoDB implements DatabaseInterface on top of a MongoDB backend.
type MongoDB struct {
	client *mongo.Client
	db     *mongo.Database
}

func getMongoStringField(doc bson.M, keys ...string) string {
	for _, key := range keys {
		if value, ok := doc[key].(string); ok {
			return value
		}
	}
	return ""
}

/**
  parseMongoBool attempts to interpret a value as a boolean, supporting multiple types and common string representations.
  It recognizes boolean types, numeric types (where non-zero is true), and strings like "true", "false", "yes", "no", "on", "off".
  @param value - The value to interpret, which may be of various types.
  @returns (bool, bool) - The interpreted boolean value and a success flag indicating if parsing was successful.
*/
func parseMongoBool(value interface{}) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case int:
		return v != 0, true
	case int32:
		return v != 0, true
	case int64:
		return v != 0, true
	case float64:
		return v != 0, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off":
			return false, true
		}
	}
	return false, false
}

func getMongoBoolField(doc bson.M, keys ...string) bool {
	for _, key := range keys {
		if value, ok := parseMongoBool(doc[key]); ok {
			return value
		}
	}
	return false
}

func getMongoInt64Field(doc bson.M, keys ...string) int64 {
	for _, key := range keys {
		switch value := doc[key].(type) {
		case int64:
			return value
		case int32:
			return int64(value)
		case int:
			return int64(value)
		case float64:
			return int64(value)
		case string:
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

/**
  decodeMongoFileEntry converts a MongoDB document into a FileEntry struct, handling various field naming conventions and types for compatibility with older collections.
  @param doc - The BSON document retrieved from MongoDB representing a file entry.
  @returns models.FileEntry - The resulting FileEntry struct with normalized fields.
*/
func decodeMongoFileEntry(doc bson.M) models.FileEntry {
	id := getMongoStringField(doc, "id")
	if id == "" {
		if objectID, ok := doc["_id"].(primitive.ObjectID); ok {
			id = objectID.Hex()
		}
	}
	return models.FileEntry{
		ID:          id,
		Name:        getMongoStringField(doc, "name", "filename"),
		Link:        getMongoStringField(doc, "link"),
		Size:        getMongoInt64Field(doc, "size"),
		UploadedAt:  getMongoStringField(doc, "uploaded_at", "uploadedat", "upload_date"),
		IsPrivate:   getMongoBoolField(doc, "is_private", "isprivate"),
		DriveID:     getMongoStringField(doc, "drive_id", "driveid"),
		StoragePath: getMongoStringField(doc, "storage_path", "storagepath"),
	}
}

/**
  normalizeFileDocuments iterates through all documents in the "files" collection and updates them to ensure they have consistent field names and types.
  @param none - This function does not accept parameters.
  @returns error - An error if the operation fails during iteration or updating.
*/
func (m *MongoDB) normalizeFileDocuments() error {
	if m.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	collection := m.db.Collection("files")
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		objectID, ok := doc["_id"].(primitive.ObjectID)
		if !ok {
			continue
		}
		file := decodeMongoFileEntry(doc)
		if file.ID == "" || file.Link == "" {
			continue
		}
		if file.DriveID == "" {
			file.DriveID = models.LocalDriveID
		}
		if file.StoragePath == "" {
			file.StoragePath = file.ID + path.Ext(file.Name)
		}
		_, err := collection.UpdateByID(ctx, objectID, bson.M{"$set": bson.M{
			"id":           file.ID,
			"name":         file.Name,
			"link":         file.Link,
			"size":         file.Size,
			"uploaded_at":  file.UploadedAt,
			"is_private":   file.IsPrivate,
			"drive_id":     file.DriveID,
			"storage_path": file.StoragePath,
			"uploadedat":   file.UploadedAt,
			"isprivate":    file.IsPrivate,
		}})
		if err != nil {
			return err
		}
	}
	return cursor.Err()
}

func appendMongoAuthSource(uri string, authSource string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	if query.Get("authSource") == "" {
		query.Set("authSource", authSource)
		parsed.RawQuery = query.Encode()
	}
	return parsed.String(), nil
}

/**
  detectLogoMime attempts to determine the MIME type of a logo based on its content.
  It checks for PNG signatures and SVG tags to identify supported formats.
  @param content - The byte slice containing the logo data.
  @returns string - The detected MIME type ("image/png", "image/svg+xml") or an empty string if unsupported.
*/
func (m *MongoDB) connect(uri string) (*mongo.Client, string, error) {
	cs, err := connstring.ParseAndValidate(uri)
	if err != nil {
		Debugf("MongoDB connection string validation failed: %v", err)
		return nil, "", fmt.Errorf("invalid MongoDB URL: %v", err)
	}
	dbName := cs.Database
	if dbName == "" {
		dbName = "fileline"
	}
	Debugf("Connecting to MongoDB hosts=%v database=%q", cs.Hosts, dbName)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		Debugf("MongoDB connect failed: %v", err)
		return nil, "", fmt.Errorf("failed to connect to MongoDB: %v", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		Debugf("MongoDB ping failed: %v", err)
		Debugf("Disconnecting MongoDB client after failed ping")
		_ = client.Disconnect(context.Background())
		return nil, "", fmt.Errorf("failed to ping MongoDB: %v", err)
	}
	db := client.Database(dbName)
	err = db.Collection("config").FindOne(ctx, bson.M{}).Err()
	if err != nil && err != mongo.ErrNoDocuments {
		Debugf("MongoDB access check failed for database=%q: %v", dbName, err)
		Debugf("Disconnecting MongoDB client after failed access check")
		_ = client.Disconnect(context.Background())
		return nil, "", fmt.Errorf("failed to access MongoDB database %q: %v", dbName, err)
	}
	Debugf("MongoDB connection established database=%q", dbName)
	return client, dbName, nil
}

/**
  Load connects to MongoDB, validates access, and prepares required collections.
  @param none - This function does not accept parameters.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) Load() error {
	if m.client != nil {
		Debugf("Disconnecting previous MongoDB client before reconnect")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = m.client.Disconnect(ctx)
		cancel()
		m.client = nil
		m.db = nil
	}
	cs, err := connstring.ParseAndValidate(Config.MongoURL)
	if err != nil {
		Debugf("MongoDB Load failed: invalid URL: %v", err)
		return fmt.Errorf("invalid MongoDB URL: %v", err)
	}
	client, dbName, err := m.connect(Config.MongoURL)
	if err != nil && cs.Username != "" && cs.AuthSource == "" {
		Debugf("MongoDB primary connect failed, retrying with authSource=admin")
		fallbackURL, fallbackURLErr := appendMongoAuthSource(Config.MongoURL, "admin")
		if fallbackURLErr == nil {
			fallbackClient, fallbackDBName, fallbackErr := m.connect(fallbackURL)
			if fallbackErr == nil {
				client = fallbackClient
				dbName = fallbackDBName
				err = nil
				Debugf("MongoDB connected using authSource=admin fallback")
			} else {
				err = fmt.Errorf("%v (also failed retry with authSource=admin: %v)", err, fallbackErr)
			}
		}
	}
	if err != nil {
		Debugf("MongoDB Load failed: %v", err)
		return err
	}
	m.client = client
	m.db = client.Database(dbName)
	// Touch collections up-front so first request does not pay collection initialization cost.
	collections := []string{"users", "files", "settings", "chunk_uploads", "config"}
	for _, collName := range collections {
		m.db.Collection(collName)
	}
	if err := m.normalizeFileDocuments(); err != nil {
		Debugf("MongoDB normalization failed: %v", err)
		return fmt.Errorf("failed to normalize MongoDB files collection: %v", err)
	}
	Debugf("MongoDB Load completed for database=%q", dbName)
	return nil
}

/**
  Save is a no-op because MongoDB writes are persisted per operation.
  @param none - This function does not accept parameters.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) Save() error {
	// MongoDB auto-saves, nothing to do
	return nil
}

/**
  GetUser returns the single user record used by the application.
  @param none - This function does not accept parameters.
  @returns *models.User - The matching value, or nil when not found.
*/
func (m *MongoDB) GetUser() *models.User {
	if m.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user models.User
	err := m.db.Collection("users").FindOne(ctx, bson.M{}).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

/**
  SetUser replaces the single user document used by this app instance.
  @param user - The user record to persist.
  @returns void
*/
func (m *MongoDB) SetUser(user *models.User) {
	if m.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// FileLine keeps a single managed account, so replace semantics are explicit.
	m.db.Collection("users").DeleteMany(ctx, bson.M{})
	m.db.Collection("users").InsertOne(ctx, user)
}

/**
  GetFiles returns all stored file metadata entries.
  @param none - This function does not accept parameters.
  @returns []models.FileEntry - The resulting collection.
*/
func (m *MongoDB) GetFiles() []models.FileEntry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cursor, err := m.db.Collection("files").Find(ctx, bson.M{})
	if err != nil {
		return []models.FileEntry{}
	}
	defer cursor.Close(ctx)
	files := []models.FileEntry{}
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		file := decodeMongoFileEntry(doc)
		if file.ID == "" || file.Link == "" {
			continue
		}
		files = append(files, file)
	}
	if err := cursor.Err(); err != nil {
		return []models.FileEntry{}
	}
	return files
}

/**
  AddFile stores a new file metadata entry.
  @param file - The file entry to store.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) AddFile(file models.FileEntry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.db.Collection("files").InsertOne(ctx, bson.M{
		"id":           file.ID,
		"name":         file.Name,
		"link":         file.Link,
		"size":         file.Size,
		"uploaded_at":  file.UploadedAt,
		"drive_id":     file.DriveID,
		"storage_path": file.StoragePath,
		// Keep legacy keys in sync for older collections created before normalized BSON mapping.
		"uploadedat": file.UploadedAt,
		"is_private": file.IsPrivate,
		"isprivate":  file.IsPrivate,
	})
	return err
}

/**
  UpdateFile updates mutable fields of a stored file entry.
  @param id - The identifier to process.
  @param name - The file name.
  @param link - The public link value.
  @param isPrivate - Whether the file should be private.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) UpdateFile(id string, name, link string, isPrivate bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	update := bson.M{"$set": bson.M{
		"name":       name,
		"link":       link,
		"isprivate":  isPrivate,
		"is_private": isPrivate,
	}}
	result, err := m.db.Collection("files").UpdateOne(
		ctx,
		bson.M{"id": id},
		update,
	)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		objectID, parseErr := primitive.ObjectIDFromHex(id)
		if parseErr == nil {
			result, err = m.db.Collection("files").UpdateOne(
				ctx,
				bson.M{"_id": objectID},
				update,
			)
			if err != nil {
				return err
			}
		}
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("file not found")
	}
	return nil
}

/**
  DeleteFile removes a file metadata entry by ID.
  @param fileID - The file identifier.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) DeleteFile(fileID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := m.db.Collection("files").DeleteOne(ctx, bson.M{"id": fileID})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		objectID, parseErr := primitive.ObjectIDFromHex(fileID)
		if parseErr == nil {
			_, err = m.db.Collection("files").DeleteOne(ctx, bson.M{"_id": objectID})
			return err
		}
	}
	return nil
}

/**
  GetFileByID returns one file by internal ID.
  @param fileID - The file identifier.
  @returns *models.FileEntry - The matching value, or nil when not found.
*/
func (m *MongoDB) GetFileByID(fileID string) *models.FileEntry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var doc bson.M
	err := m.db.Collection("files").FindOne(ctx, bson.M{"id": fileID}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		objectID, parseErr := primitive.ObjectIDFromHex(fileID)
		if parseErr == nil {
			err = m.db.Collection("files").FindOne(ctx, bson.M{"_id": objectID}).Decode(&doc)
		}
	}
	if err != nil {
		return nil
	}
	file := decodeMongoFileEntry(doc)
	if file.ID == "" {
		file.ID = fileID
	}
	if file.Link == "" {
		return nil
	}
	return &file
}

/**
  GetFileByLink returns one file by public link token.
  @param link - The public link value.
  @returns *models.FileEntry - The matching value, or nil when not found.
*/
func (m *MongoDB) GetFileByLink(link string) *models.FileEntry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var doc bson.M
	err := m.db.Collection("files").FindOne(ctx, bson.M{"link": link}).Decode(&doc)
	if err != nil {
		return nil
	}
	file := decodeMongoFileEntry(doc)
	if file.ID == "" {
		return nil
	}
	return &file
}

/**
  GetSettings returns stored settings, with defaults when absent.
  @param none - This function does not accept parameters.
  @returns models.AppSettings - The resulting value.
*/
func (m *MongoDB) GetSettings() models.AppSettings {
	defaults := models.AppSettings{
		Theme:          "dark-blue",
		AccentColor:    "#3b82f6",
		Language:       "en",
		ChunkSizeBytes: models.DefaultChunkSize,
		ChunkThreshold: models.DefaultChunkThreshold,
		MaxFileSize:    0,
		CustomLogo:     "",
	}
	if m.db == nil {
		return defaults
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var doc bson.M
	err := m.db.Collection("settings").FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		return defaults
	}
	settings := defaults
	if theme := getMongoStringField(doc, "theme"); theme != "" {
		settings.Theme = theme
	}
	if accent := getMongoStringField(doc, "accent_color", "accentcolor"); accent != "" {
		settings.AccentColor = accent
	}
	if language := getMongoStringField(doc, "language"); language != "" {
		settings.Language = language
	}
	if chunkSize := getMongoInt64Field(doc, "chunk_size_bytes", "chunksizebytes"); chunkSize > 0 {
		settings.ChunkSizeBytes = chunkSize
	}
	if chunkThreshold := getMongoInt64Field(doc, "chunk_threshold", "chunkthreshold"); chunkThreshold > 0 {
		settings.ChunkThreshold = chunkThreshold
	}
	if maxFileSize := getMongoInt64Field(doc, "max_file_size", "maxfilesize"); maxFileSize >= 0 {
		settings.MaxFileSize = maxFileSize
	}
	if customLogo := getMongoStringField(doc, "custom_logo", "customlogo"); customLogo != "" {
		settings.CustomLogo = customLogo
	}
	if raw := getMongoStringField(doc, "storage_drives", "storagedrives"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &settings.StorageDrives)
	}
	return settings
}

/**
  UpdateSettings replaces the single settings document.
  @param settings - The application settings payload.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) UpdateSettings(settings models.AppSettings) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// FileLine persists one settings document; replace for deterministic reads.
	m.db.Collection("settings").DeleteMany(ctx, bson.M{})
	storageDrivesJSON, _ := json.Marshal(settings.StorageDrives)
	_, err := m.db.Collection("settings").InsertOne(ctx, bson.M{
		"theme":            settings.Theme,
		"accent_color":     settings.AccentColor,
		"language":         settings.Language,
		"chunk_size_bytes": settings.ChunkSizeBytes,
		"chunk_threshold":  settings.ChunkThreshold,
		"max_file_size":    settings.MaxFileSize,
		"custom_logo":      settings.CustomLogo,
		"storage_drives":   string(storageDrivesJSON),
		"accentcolor":      settings.AccentColor,
		"chunksizebytes":   settings.ChunkSizeBytes,
		"chunkthreshold":   settings.ChunkThreshold,
		"maxfilesize":      settings.MaxFileSize,
		"customlogo":       settings.CustomLogo,
		"storagedrives":    string(storageDrivesJSON),
	})
	return err
}

/**
  GetChunkUploads returns all in-flight chunk upload states.
  @param none - This function does not accept parameters.
  @returns []models.ChunkUpload - The resulting collection.
*/
func (m *MongoDB) GetChunkUploads() []models.ChunkUpload {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cursor, err := m.db.Collection("chunk_uploads").Find(ctx, bson.M{})
	if err != nil {
		return []models.ChunkUpload{}
	}
	defer cursor.Close(ctx)
	var chunks []models.ChunkUpload
	if err := cursor.All(ctx, &chunks); err != nil {
		return []models.ChunkUpload{}
	}
	return chunks
}

/**
  AddChunkUpload stores tracking data for a chunked upload.
  @param chunk - The chunk upload payload.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) AddChunkUpload(chunk models.ChunkUpload) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.db.Collection("chunk_uploads").InsertOne(ctx, chunk)
	return err
}

/**
  RemoveChunkUpload removes tracking data after upload completion or cleanup.
  @param uploadID - The chunk upload identifier.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) RemoveChunkUpload(uploadID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.db.Collection("chunk_uploads").DeleteOne(ctx, bson.M{"id": uploadID})
	return err
}

/**
  GetChunkUpload returns one tracked chunked upload by ID.
  @param uploadID - The chunk upload identifier.
  @returns *models.ChunkUpload - The matching value, or nil when not found.
*/
func (m *MongoDB) GetChunkUpload(uploadID string) *models.ChunkUpload {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var chunk models.ChunkUpload
	err := m.db.Collection("chunk_uploads").FindOne(ctx, bson.M{"id": uploadID}).Decode(&chunk)
	if err != nil {
		return nil
	}
	return &chunk
}

/**
  IsConfigured reads the setup flag from MongoDB and surfaces read errors globally.
  @param none - This function does not accept parameters.
  @returns bool - True when is configured is satisfied; otherwise false.
*/
func (m *MongoDB) IsConfigured() bool {
	if m.db == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var result bson.M
	err := m.db.Collection("config").FindOne(ctx, bson.M{"key": "configured"}).Decode(&result)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			ConnectionError = err
		} else {
			ConnectionError = nil
		}
		return false
	}
	ConnectionError = nil
	configured, ok := result["value"].(bool)
	return ok && configured
}

/**
  SetConfigured upserts the setup-completion flag.
  @param configured - Whether initial setup is complete.
  @returns void
*/
func (m *MongoDB) SetConfigured(configured bool) {
	if m.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.db.Collection("config").UpdateOne(
		ctx,
		bson.M{"key": "configured"},
		bson.M{"$set": bson.M{"key": "configured", "value": configured}},
		options.Update().SetUpsert(true),
	)
}

/**
  LinkExists checks if a public link is already taken.
  @param link - The public link value.
  @returns bool - True when link exists is satisfied; otherwise false.
*/
func (m *MongoDB) LinkExists(link string) bool {
	files := m.GetFiles()
	for _, f := range files {
		if f.Link == link {
			return true
		}
	}
	return false
}

/**
  InitDefaults initializes the database with defaults.
  @param none - This function does not accept parameters.
  @returns void
*/
func (m *MongoDB) InitDefaults() {
	// MongoDB doesn't need explicit defaults, collections auto-create
}

/**
  UpdateChunkReceived marks a chunk as received.
  @param id - The identifier to process.
  @param chunkIndex - The zero-based chunk index.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) UpdateChunkReceived(id string, chunkIndex int) error {
	chunk := m.GetChunkUpload(id)
	if chunk == nil {
		return fmt.Errorf("chunk upload not found")
	}
	if chunkIndex >= 0 && chunkIndex < len(chunk.Received) {
		chunk.Received[chunkIndex] = true
		return m.UpdateChunkUpload(*chunk)
	}
	return fmt.Errorf("invalid chunk index")
}

/**
  UpdateChunkUpload is a helper method (not in interface).
  @param chunk - The chunk upload payload.
  @returns error - An error if the operation fails.
*/
func (m *MongoDB) UpdateChunkUpload(chunk models.ChunkUpload) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.db.Collection("chunk_uploads").UpdateOne(
		ctx,
		bson.M{"id": chunk.ID},
		bson.M{"$set": chunk},
	)
	return err
}
