package translations

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed *.json
var translationsFS embed.FS

var (
	translations = make(map[string]map[string]interface{})
	mu           sync.RWMutex
)

func init() {
	_ = Load()
}

// FS returns the underlying embed.FS containing all translation files.
func FS() embed.FS {
	return translationsFS
}

// Load hydrates all embedded language packs into memory.
func Load() error {
	entries, err := translationsFS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("reading translations directory: %w", err)
	}

	newTrans := make(map[string]map[string]interface{})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := translationsFS.ReadFile(entry.Name())
		if err != nil {
			return fmt.Errorf("reading translation file %s: %w", entry.Name(), err)
		}

		var trans map[string]interface{}
		if err := json.Unmarshal(data, &trans); err != nil {
			return fmt.Errorf("unmarshaling translation file %s: %w", entry.Name(), err)
		}

		lang := strings.TrimSuffix(entry.Name(), ".json")
		newTrans[lang] = trans
	}

	mu.Lock()
	translations = newTrans
	mu.Unlock()
	return nil
}

// Get returns a translation dictionary for the requested language.
func Get(lang string) map[string]interface{} {
	mu.RLock()
	defer mu.RUnlock()
	if trans, ok := translations[lang]; ok {
		return trans
	}
	if trans, ok := translations["en"]; ok {
		return trans
	}
	return make(map[string]interface{})
}

// GetString returns a direct string translation or the key itself as fallback.
func GetString(lang, key string) string {
	trans := Get(lang)
	if val, ok := trans[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return key
}

// LanguageNames maps language codes to their native names.
var LanguageNames = map[string]string{
	"en": "English",
	"pl": "Polski",
	"cz": "Čeština",
	"sk": "Slovenčina",
	"de": "Deutsch",
	"nl": "Nederlands",
	"it": "Italiano",
	"fr": "Français",
	"es": "Español",
}

// AvailableLanguages returns currently loaded language codes in deterministic sorted order.
func AvailableLanguages() []string {
	mu.RLock()
	defer mu.RUnlock()
	langs := make([]string, 0, len(translations))
	for lang := range translations {
		langs = append(langs, lang)
	}
	sort.Strings(langs)
	return langs
}
