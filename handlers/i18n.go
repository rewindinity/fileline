package handlers

import (
	"fileline/database"
	i18n "fileline/translations"
)

/**
  GetLang returns the active UI language preference.
  @param none - This function does not accept parameters.
  @returns string - The language code.
*/
func GetLang() string {
	lang := database.GetSettings().Language
	// Keep English as a stable default for first-run and invalid state fallback.
	if lang == "" {
		return "en"
	}
	return lang
}

/**
  GetTranslations resolves the current language dictionary used by templates.
  @param none - This function does not accept parameters.
  @returns map[string]interface{} - The resulting map value.
*/
func GetTranslations() map[string]interface{} {
	return i18n.Get(GetLang())
}

/**
  T is a something that templates can call to get the current language dictionary.
  @param none - This function does not accept parameters.
  @returns map[string]interface{} - The resulting map value.
*/
func T() map[string]interface{} {
	return GetTranslations()
}
