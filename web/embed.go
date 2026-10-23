package web

import (
	"embed"
	"io/fs"
	"mime"
)

//go:embed templates
var TemplatesFS embed.FS

//go:embed static
var StaticFS embed.FS

func init() {
	// Ensure common web fonts and vector graphics have correct MIME types
	// regardless of host system mime configurations (e.g. distroless/scratch containers).
	_ = mime.AddExtensionType(".woff2", "font/woff2")
	_ = mime.AddExtensionType(".woff", "font/woff")
	_ = mime.AddExtensionType(".svg", "image/svg+xml")
	_ = mime.AddExtensionType(".css", "text/css; charset=utf-8")
	_ = mime.AddExtensionType(".js", "text/javascript; charset=utf-8")
}

// Templates returns the fs.FS scoped to the templates/ directory.
func Templates() fs.FS {
	sub, err := fs.Sub(TemplatesFS, "templates")
	if err != nil {
		panic("web: failed to sub templates directory: " + err.Error())
	}
	return sub
}

// Static returns the fs.FS scoped to the static/ directory.
func Static() fs.FS {
	sub, err := fs.Sub(StaticFS, "static")
	if err != nil {
		panic("web: failed to sub static directory: " + err.Error())
	}
	return sub
}
