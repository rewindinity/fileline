package i18n

import (
	"embed"
	"encoding/json"
	"sync"
)

//go:embed *.json
var translationsFS embed.FS

// translations stores language dictionaries loaded from embedded JSON resources.
var (
	translations = make(map[string]map[string]interface{})
	mu           sync.RWMutex
)

/**
  Load hydrates all known language packs into memory.
  @param none - This function does not accept parameters.
  @returns error - An error if the operation fails.
*/
func Load() error {
	files := []string{"en.json", "pl.json", "de.json", "fr.json", "cz.json"}
	for _, file := range files {
		data, err := translationsFS.ReadFile(file)
		if err != nil {
			// Missing language packs are tolerated so the app can still boot.
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

/**
  Get returns a translation dictionary for the requested language.
  @param lang - The language code.
  @returns map[string]interface{} - The resulting map value.
*/
func Get(lang string) map[string]interface{} {
	mu.RLock()
	defer mu.RUnlock()
	if trans, ok := translations[lang]; ok {
		return trans
	}
	// Fallback to English
	if trans, ok := translations["en"]; ok {
		return trans
	}
	return make(map[string]interface{})
}

/**
  GetString returns a direct string translation or the key itself as fallback.
  @param lang - The language code.
  @param key - The translation key.
  @returns string - The resulting string value.
*/
func GetString(lang, key string) string {
	trans := Get(lang)
	if val, ok := trans[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return key
}

/**
  AvailableLanguages returns currently loaded language codes.
  @param none - This function does not accept parameters.
  @returns []string - The resulting collection.
*/
func AvailableLanguages() []string {
	mu.RLock()
	defer mu.RUnlock()
	langs := make([]string, 0, len(translations))
	for lang := range translations {
		langs = append(langs, lang)
	}
	return langs
}
