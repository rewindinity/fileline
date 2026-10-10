package translations

import (
	"embed"
	"encoding/json"
	"sync"
)

//go:embed *.json
var translationsFS embed.FS

var (
	translations = make(map[string]map[string]interface{})
	mu           sync.RWMutex
)

// Load hydrates all known language packs into memory.
func Load() error {
	files := []string{"en.json", "pl.json", "cz.json", "sk.json", "de.json", "nl.json", "it.json", "fr.json", "es.json"}
	for _, file := range files {
		data, err := translationsFS.ReadFile(file)
		if err != nil {
			continue
		}
		var trans map[string]interface{}
		if err := json.Unmarshal(data, &trans); err != nil {
			continue
		}
		lang := file[:len(file)-5] // Remove .json
		mu.Lock()
		translations[lang] = trans
		mu.Unlock()
	}
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

// AvailableLanguages returns currently loaded language codes.
func AvailableLanguages() []string {
	mu.RLock()
	defer mu.RUnlock()
	langs := make([]string, 0, len(translations))
	for lang := range translations {
		langs = append(langs, lang)
	}
	return langs
}
