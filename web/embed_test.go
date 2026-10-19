package web

import (
	"html/template"
	"io/fs"
	"mime"
	"testing"
)

func TestTemplatesFS(t *testing.T) {
	tmplFS := Templates()
	if tmplFS == nil {
		t.Fatal("Templates() returned nil")
	}

	requiredTemplates := []string{
		"404.html",
		"base.html",
		"dashboard.html",
		"edit_file.html",
		"embed_file.html",
		"files.html",
		"login_2fa.html",
		"login.html",
		"reset_password.html",
		"settings_account.html",
		"settings_appearance.html",
		"settings_embed.html",
		"settings_storage.html",
		"settings_subusers.html",
		"settings.html",
		"setup.html",
	}

	for _, name := range requiredTemplates {
		data, err := fs.ReadFile(tmplFS, name)
		if err != nil {
			t.Errorf("failed to read embedded template %s: %v", name, err)
		} else if len(data) == 0 {
			t.Errorf("embedded template %s is empty", name)
		}
	}
}

func TestStaticFS(t *testing.T) {
	staticFS := Static()
	if staticFS == nil {
		t.Fatal("Static() returned nil")
	}

	requiredFiles := []string{
		"css/style.css",
		"css/themes.css",
		"icons.css",
		"logo.svg",
		"logo.png",
		"qrcode.min.js",
		"fonts/Outfit-Regular.woff2",
		"fonts/Outfit-Medium.woff2",
		"fonts/Outfit-SemiBold.woff2",
		"fonts/Outfit-Bold.woff2",
		"fonts/Outfit-ExtraBold.woff2",
		"icons/bx-check.svg",
		"icons/bxs-dashboard.svg",
		"icons/bxs-folder.svg",
	}

	for _, name := range requiredFiles {
		data, err := fs.ReadFile(staticFS, name)
		if err != nil {
			t.Errorf("failed to read embedded static file %s: %v", name, err)
		} else if len(data) == 0 {
			t.Errorf("embedded static file %s is empty", name)
		}
	}

	// Verify icon directory has expected SVG count
	iconEntries, err := fs.ReadDir(staticFS, "icons")
	if err != nil {
		t.Fatalf("failed to read embedded static/icons directory: %v", err)
	}
	if len(iconEntries) < 40 {
		t.Errorf("expected at least 40 embedded icons, got %d", len(iconEntries))
	}

	// Verify MIME registrations
	if ct := mime.TypeByExtension(".woff2"); ct != "font/woff2" {
		t.Errorf("expected mime for .woff2 to be 'font/woff2', got %q", ct)
	}
	if ct := mime.TypeByExtension(".svg"); ct != "image/svg+xml" {
		t.Errorf("expected mime for .svg to be 'image/svg+xml', got %q", ct)
	}
}

func TestEmbeddedTemplatesParse(t *testing.T) {
	tmplFS := Templates()
	funcs := template.FuncMap{
		"FormatSize":       func(b int64) string { return "1 MB" },
		"FormatPercent":    func(p float64) string { return "10.0%" },
		"FormatPercentRaw": func(p float64) string { return "10.0" },
		"FormatTime":       func(t any) string { return "Jan 01, 2026 12:00" },
		"T":                func(lang, key string) string { return key },
	}

	pages := []string{
		"setup.html", "login.html", "login_2fa.html", "reset_password.html", "dashboard.html",
		"404.html", "edit_file.html", "files.html", "settings.html", "settings_appearance.html",
		"settings_embed.html", "settings_account.html", "settings_storage.html", "settings_subusers.html",
	}

	for _, page := range pages {
		tmpl := template.New("base.html").Funcs(funcs)
		_, err := tmpl.ParseFS(tmplFS, "base.html", page)
		if err != nil {
			t.Errorf("failed to parse page template %s with base.html from embedded FS: %v", page, err)
		}
	}

	tmplEmbed := template.New("embed_file.html").Funcs(funcs)
	if _, err := tmplEmbed.ParseFS(tmplFS, "embed_file.html"); err != nil {
		t.Errorf("failed to parse embed_file.html from embedded FS: %v", err)
	}
}
