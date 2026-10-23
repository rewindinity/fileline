package server

import (
	"fileline/internal/config"
	"fileline/internal/db"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestFormatCSSSingleLine(t *testing.T) {
	input := `
	/* Custom primary styles */
	:root {
		--accent-primary: #2563eb;
		--bg-color: #ffffff;
	}

	/* Card element */
	.card {
		margin: 1rem;
		padding: 0.5rem;
	}
	`
	out := formatCSSSingleLine([]byte(input))
	outStr := string(out)

	if strings.Contains(outStr, "\n") {
		t.Errorf("expected single line CSS, got newlines: %q", outStr)
	}
	if !strings.Contains(outStr, "/* Custom primary styles */") {
		t.Errorf("expected comment to be preserved in CSS")
	}
	if !strings.Contains(outStr, "--accent-primary: #2563eb;") {
		t.Errorf("expected variables to be preserved in CSS")
	}
	if !strings.Contains(outStr, ".card {margin: 1rem;") {
		t.Errorf("expected selectors to be preserved in CSS")
	}
}

func TestFormatJSSingleLine(t *testing.T) {
	input := `
	// Initialize variable
	let count = 0;
	// Function to increment
	function increment() {
		count++; // inline comment
		return count;
	}
	increment();
	`
	out := formatJSSingleLine([]byte(input))
	outStr := string(out)

	if strings.Contains(outStr, "\n") {
		t.Errorf("expected single line JS, got newlines: %q", outStr)
	}
	if !strings.Contains(outStr, "/* Initialize variable */") {
		t.Errorf("expected single-line comment converted to block comment")
	}
	if !strings.Contains(outStr, "function increment()") {
		t.Errorf("expected function definition preserved")
	}
	if !strings.Contains(outStr, "increment()") {
		t.Errorf("expected increment call preserved")
	}
}

func TestFormatHTMLSingleLine(t *testing.T) {
	input := `
	<!DOCTYPE html>
	<html>
	<!-- Top level comment -->
	<head>
		<title>FileLine</title>
		<style>
			/* Inlined CSS */
			body {
				margin: 0;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>Hello World</h1>
			<p>Description text</p>
		</div>
		<pre>
Line 1
Line 2
		</pre>
		<script>
			// Inlined script
			const app = "FileLine";
			console.log(app);
		</script>
	</body>
	</html>
	`
	out := formatHTMLSingleLine([]byte(input))
	outStr := string(out)

	if !strings.Contains(outStr, "<!-- Top level comment -->") {
		t.Errorf("expected HTML comment to be preserved")
	}
	if !strings.Contains(outStr, "<h1>Hello World</h1>") {
		t.Errorf("expected heading preserved")
	}
	if !strings.Contains(outStr, "/* Inlined CSS */") {
		t.Errorf("expected inline style comment preserved")
	}
	if !strings.Contains(outStr, "/* Inlined script */") {
		t.Errorf("expected inline script comment preserved")
	}
	if !strings.Contains(outStr, "<pre>\nLine 1\nLine 2\n\t\t</pre>") {
		t.Errorf("expected <pre> block newlines to be preserved verbatim")
	}
}

func TestFormatXMLSingleLine(t *testing.T) {
	input := `
	<svg viewBox="0 0 24 24">
		<!-- Check icon -->
		<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
	</svg>
	`
	out := formatXMLSingleLine([]byte(input))
	outStr := string(out)

	if strings.Contains(outStr, "\n") {
		t.Errorf("expected single line XML/SVG, got newlines: %q", outStr)
	}
	if !strings.Contains(outStr, "<!-- Check icon -->") {
		t.Errorf("expected XML comment preserved")
	}
	if !strings.Contains(outStr, "<path d=\"M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z\"/>") {
		t.Errorf("expected SVG path preserved")
	}
}

func TestAllTemplatesRenderJS(t *testing.T) {
	cfg := config.DefaultConfig()
	srv := New(&cfg, nil)
	templates := []string{
		"dashboard.html",
		"files.html",
		"settings.html",
		"settings_account.html",
		"settings_appearance.html",
		"settings_storage.html",
		"settings_embed.html",
		"settings_subusers.html",
		"embed_file.html",
		"edit_file.html",
		"login.html",
		"login_2fa.html",
		"reset_password.html",
		"setup.html",
		"404.html",
	}

	for _, tmpl := range templates {
		t.Run(tmpl, func(t *testing.T) {
			rr := httptest.NewRecorder()
			srv.renderTemplate(rr, nil, tmpl, map[string]interface{}{
				"Title":          "Test",
				"Files":          []interface{}{},
				"TotalUsedBytes": int64(0),
				"EnabledDrives":  []config.DriveView{},
				"User":           &db.User{Username: "testuser", Role: "admin"},
				"Username":       "testuser",
				"Config":         cfg.SanitizedView(),
			})
			html := rr.Body.String()
			rest := html
			scriptCount := 0
			for {
				start := strings.Index(rest, "<script")
				if start == -1 {
					break
				}
				tagEnd := strings.Index(rest[start:], ">")
				if tagEnd == -1 {
					break
				}
				rest = rest[start+tagEnd+1:]
				end := strings.Index(rest, "</script>")
				if end == -1 {
					break
				}
				js := strings.TrimSpace(rest[:end])
				rest = rest[end+9:]
				if js == "" {
					continue
				}
				scriptCount++
				cmd := exec.Command("node", "--check")
				cmd.Stdin = strings.NewReader(js)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("[%s] JS syntax error in script #%d: %v\nOutput: %s\nJS: %s", tmpl, scriptCount, err, out, js)
				}
			}
		})
	}
}
