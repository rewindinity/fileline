package translations

import (
	"sort"
	"testing"
)

func TestTranslationsLoad(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatalf("Failed to load translations: %v", err)
	}

	langs := []string{"en", "pl", "cz", "sk", "de", "nl", "it", "fr", "es"}
	for _, lang := range langs {
		data := Get(lang)
		if len(data) == 0 {
			t.Errorf("Language %s has no translations", lang)
		}
	}

	// Verify all languages have the exact same set of keys
	enData := Get("en")
	for _, lang := range langs {
		if lang == "en" {
			continue
		}
		langData := Get(lang)
		for k := range enData {
			if _, ok := langData[k]; !ok {
				t.Errorf("Language %s is missing key: %q", lang, k)
			}
		}
		for k := range langData {
			if _, ok := enData[k]; !ok {
				t.Errorf("Language %s has extra key: %q", lang, k)
			}
		}
	}
}

func TestGetString(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatalf("Failed to load translations: %v", err)
	}

	if val := GetString("pl", "Files"); val != "Pliki" {
		t.Errorf("Expected 'Pliki', got %q", val)
	}
	if val := GetString("de", "Files"); val != "Dateien" {
		t.Errorf("Expected 'Dateien', got %q", val)
	}
	// Fallback to en if key exists
	if val := GetString("nonexistent", "Files"); val != "Files" {
		t.Errorf("Expected fallback 'Files', got %q", val)
	}
	// Fallback to key itself if not in any dictionary
	if val := GetString("en", "UnknownKey123"); val != "UnknownKey123" {
		t.Errorf("Expected key fallback 'UnknownKey123', got %q", val)
	}
}

func TestFSAndAvailableLanguages(t *testing.T) {
	fsys := FS()
	data, err := fsys.ReadFile("en.json")
	if err != nil {
		t.Fatalf("expected to read en.json from FS(): %v", err)
	}
	if len(data) == 0 {
		t.Errorf("en.json in FS() is empty")
	}

	langs := AvailableLanguages()
	if len(langs) == 0 {
		t.Fatal("AvailableLanguages() returned empty slice")
	}
	if !sort.StringsAreSorted(langs) {
		t.Errorf("AvailableLanguages() is not sorted: %v", langs)
	}
}
