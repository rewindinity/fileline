package server

import (
	"bytes"
	"strings"
	"unicode"
)

// formatCSSSingleLine collapses CSS lines and whitespace into a single line while preserving all comments.
func formatCSSSingleLine(css []byte) []byte {
	if len(css) == 0 {
		return nil
	}
	lines := strings.Split(string(css), "\n")
	var sb strings.Builder
	sb.Grow(len(css))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if sb.Len() > 0 {
			last := sb.String()[sb.Len()-1]
			// Avoid adding redundant spaces around punctuation
			if last != '{' && last != '}' && last != ';' && last != ':' && last != ',' {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(trimmed)
	}
	return []byte(sb.String())
}

type jsParserState int

const (
	stateNormal jsParserState = iota
	stateTemplate
	stateExpr
)

// formatJSSingleLine collapses JavaScript lines into a single line while preserving all comments.
// Single-line comments (// ...) are converted to block comments (/* ... */) so that subsequent
// statements are not commented out when collapsed into one line.
// Multi-line template literals (`...`) are tracked so that semicolons are never inserted into template text.
func formatJSSingleLine(js []byte) []byte {
	if len(js) == 0 {
		return nil
	}
	lines := strings.Split(string(js), "\n")
	var sb strings.Builder
	sb.Grow(len(js))

	var stack []jsParserState
	var exprDepths []int
	inSingle := false
	inDouble := false

	isTemplateText := func() bool {
		return len(stack) > 0 && stack[len(stack)-1] == stateTemplate
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		wasTemplateText := isTemplateText()

		// Convert single-line comments to block comments outside string and template literals
		if !wasTemplateText && !inSingle && !inDouble && len(stack) == 0 {
			if strings.HasPrefix(trimmed, "//") {
				commentContent := strings.TrimSpace(strings.TrimPrefix(trimmed, "//"))
				trimmed = "/* " + commentContent + " */"
			} else {
				trimmed = convertInlineJSComment(trimmed)
			}
		}

		if sb.Len() > 0 {
			prev := sb.String()
			lastNonSpace := byte(' ')
			for i := len(prev) - 1; i >= 0; i-- {
				if !unicode.IsSpace(rune(prev[i])) {
					lastNonSpace = prev[i]
					break
				}
			}

			firstChar := trimmed[0]
			noSemicolonBefore := wasTemplateText || firstChar == '`' || lastNonSpace == '`' ||
				firstChar == '}' || firstChar == ')' || firstChar == ']' ||
				firstChar == ',' || firstChar == '.' || firstChar == ':' || firstChar == '?' ||
				firstChar == ';' || strings.HasPrefix(trimmed, "else") || strings.HasPrefix(trimmed, "catch") ||
				strings.HasPrefix(trimmed, "finally") || strings.HasPrefix(trimmed, "while") ||
				strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "||") || strings.HasPrefix(trimmed, "&&")

			// If previous line does not end with a syntax delimiter, insert semicolon or space
			if !noSemicolonBefore &&
				lastNonSpace != '{' && lastNonSpace != '}' && lastNonSpace != ';' &&
				lastNonSpace != ',' && lastNonSpace != '(' && lastNonSpace != '[' &&
				lastNonSpace != ':' && lastNonSpace != '?' && lastNonSpace != '+' &&
				lastNonSpace != '-' && lastNonSpace != '=' && lastNonSpace != '*' &&
				lastNonSpace != '/' && lastNonSpace != '!' && lastNonSpace != '&' &&
				lastNonSpace != '|' && lastNonSpace != '>' && lastNonSpace != '<' &&
				lastNonSpace != '%' && lastNonSpace != '^' && lastNonSpace != '~' &&
				lastNonSpace != '`' {
				if !strings.HasSuffix(prev, "*/") {
					sb.WriteByte(';')
				} else {
					sb.WriteByte(' ')
				}
			} else {
				sb.WriteByte(' ')
			}
		}

		// Update parser state
		escaped := false
		for i := 0; i < len(trimmed); i++ {
			ch := trimmed[i]
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}

			if inSingle {
				if ch == '\'' {
					inSingle = false
				}
				continue
			}
			if inDouble {
				if ch == '"' {
					inDouble = false
				}
				continue
			}

			currState := stateNormal
			if len(stack) > 0 {
				currState = stack[len(stack)-1]
			}

			switch currState {
			case stateNormal:
				if ch == '\'' {
					inSingle = true
				} else if ch == '"' {
					inDouble = true
				} else if ch == '`' {
					stack = append(stack, stateTemplate)
				}
			case stateTemplate:
				if ch == '`' {
					stack = stack[:len(stack)-1]
				} else if ch == '$' && i+1 < len(trimmed) && trimmed[i+1] == '{' {
					i++
					stack = append(stack, stateExpr)
					exprDepths = append(exprDepths, 1)
				}
			case stateExpr:
				if ch == '\'' {
					inSingle = true
				} else if ch == '"' {
					inDouble = true
				} else if ch == '`' {
					stack = append(stack, stateTemplate)
				} else if ch == '{' {
					exprDepths[len(exprDepths)-1]++
				} else if ch == '}' {
					exprDepths[len(exprDepths)-1]--
					if exprDepths[len(exprDepths)-1] == 0 {
						stack = stack[:len(stack)-1]
						exprDepths = exprDepths[:len(exprDepths)-1]
					}
				}
			}
		}

		sb.WriteString(trimmed)
	}
	return []byte(sb.String())
}

// convertInlineJSComment safely converts trailing // comments to /* ... */ outside string literals.
func convertInlineJSComment(line string) string {
	inSingle := false
	inDouble := false
	inBacktick := false
	escaped := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble && !inBacktick {
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle && !inBacktick {
			inDouble = !inDouble
			continue
		}
		if ch == '`' && !inSingle && !inDouble {
			inBacktick = !inBacktick
			continue
		}
		if !inSingle && !inDouble && !inBacktick && i+1 < len(line) && ch == '/' && line[i+1] == '/' {
			// Found unquoted //
			before := strings.TrimRight(line[:i], " \t")
			comment := strings.TrimSpace(line[i+2:])
			return before + " /* " + comment + " */"
		}
	}
	return line
}

// formatHTMLSingleLine collapses HTML into a single line while preserving all comments (<!-- ... -->),
// respecting <pre> and <textarea> blocks, and minifying inline <script> and <style> sections.
func formatHTMLSingleLine(html []byte) []byte {
	if len(html) == 0 {
		return nil
	}
	content := string(html)
	var sb strings.Builder
	sb.Grow(len(html))

	inPre := false
	inTextarea := false
	inScript := false
	inStyle := false

	var blockBuf strings.Builder

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)

		// Inside <pre>...</pre>
		if inPre {
			sb.WriteByte('\n')
			sb.WriteString(line)
			if strings.Contains(lower, "</pre>") {
				inPre = false
			}
			continue
		}
		if strings.Contains(lower, "<pre") && !strings.Contains(lower, "</pre>") {
			inPre = true
			if sb.Len() > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(line)
			continue
		}

		// Inside <textarea>...</textarea>
		if inTextarea {
			sb.WriteByte('\n')
			sb.WriteString(line)
			if strings.Contains(lower, "</textarea>") {
				inTextarea = false
			}
			continue
		}
		if strings.Contains(lower, "<textarea") && !strings.Contains(lower, "</textarea>") {
			inTextarea = true
			if sb.Len() > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(line)
			continue
		}

		// Inside <script>...</script>
		if inScript {
			if idx := strings.Index(lower, "</script>"); idx >= 0 {
				blockBuf.WriteString(line[:idx])
				minJS := formatJSSingleLine([]byte(blockBuf.String()))
				sb.Write(minJS)
				sb.WriteString(line[idx:])
				inScript = false
				blockBuf.Reset()
			} else {
				blockBuf.WriteString(line)
				blockBuf.WriteByte('\n')
			}
			continue
		}
		if idx := strings.Index(lower, "<script"); idx >= 0 {
			// Check if script tag closes on same line
			closeIdx := strings.Index(lower[idx:], "</script>")
			if closeIdx >= 0 {
				tagEnd := strings.Index(lower[idx:], ">")
				if tagEnd >= 0 && tagEnd < closeIdx {
					openTag := line[idx : idx+tagEnd+1]
					scriptBody := line[idx+tagEnd+1 : idx+closeIdx]
					closeTag := line[idx+closeIdx : idx+closeIdx+9]
					minJS := formatJSSingleLine([]byte(scriptBody))

					trimmedBefore := strings.TrimSpace(line[:idx])
					if trimmedBefore != "" {
						appendHTMLPart(&sb, trimmedBefore)
					}
					appendHTMLPart(&sb, openTag)
					sb.Write(minJS)
					appendHTMLPart(&sb, closeTag)
					trimmedAfter := strings.TrimSpace(line[idx+closeIdx+9:])
					if trimmedAfter != "" {
						appendHTMLPart(&sb, trimmedAfter)
					}
					continue
				}
			} else {
				// Script tag spans multiple lines
				tagEnd := strings.Index(lower[idx:], ">")
				if tagEnd >= 0 {
					inScript = true
					trimmedBefore := strings.TrimSpace(line[:idx])
					if trimmedBefore != "" {
						appendHTMLPart(&sb, trimmedBefore)
					}
					appendHTMLPart(&sb, line[idx:idx+tagEnd+1])
					blockBuf.Reset()
					blockBuf.WriteString(line[idx+tagEnd+1:])
					blockBuf.WriteByte('\n')
					continue
				}
			}
		}

		// Inside <style>...</style>
		if inStyle {
			if idx := strings.Index(lower, "</style>"); idx >= 0 {
				blockBuf.WriteString(line[:idx])
				minCSS := formatCSSSingleLine([]byte(blockBuf.String()))
				sb.Write(minCSS)
				sb.WriteString(line[idx:])
				inStyle = false
				blockBuf.Reset()
			} else {
				blockBuf.WriteString(line)
				blockBuf.WriteByte('\n')
			}
			continue
		}
		if idx := strings.Index(lower, "<style"); idx >= 0 {
			closeIdx := strings.Index(lower[idx:], "</style>")
			if closeIdx >= 0 {
				tagEnd := strings.Index(lower[idx:], ">")
				if tagEnd >= 0 && tagEnd < closeIdx {
					openTag := line[idx : idx+tagEnd+1]
					styleBody := line[idx+tagEnd+1 : idx+closeIdx]
					closeTag := line[idx+closeIdx : idx+closeIdx+8]
					minCSS := formatCSSSingleLine([]byte(styleBody))

					trimmedBefore := strings.TrimSpace(line[:idx])
					if trimmedBefore != "" {
						appendHTMLPart(&sb, trimmedBefore)
					}
					appendHTMLPart(&sb, openTag)
					sb.Write(minCSS)
					appendHTMLPart(&sb, closeTag)
					trimmedAfter := strings.TrimSpace(line[idx+closeIdx+8:])
					if trimmedAfter != "" {
						appendHTMLPart(&sb, trimmedAfter)
					}
					continue
				}
			} else {
				tagEnd := strings.Index(lower[idx:], ">")
				if tagEnd >= 0 {
					inStyle = true
					trimmedBefore := strings.TrimSpace(line[:idx])
					if trimmedBefore != "" {
						appendHTMLPart(&sb, trimmedBefore)
					}
					appendHTMLPart(&sb, line[idx:idx+tagEnd+1])
					blockBuf.Reset()
					blockBuf.WriteString(line[idx+tagEnd+1:])
					blockBuf.WriteByte('\n')
					continue
				}
			}
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		appendHTMLPart(&sb, trimmed)
	}

	return []byte(sb.String())
}

func appendHTMLPart(sb *strings.Builder, part string) {
	if sb.Len() > 0 {
		last := sb.String()[sb.Len()-1]
		first := part[0]
		// If last was '>' and next is '<', no whitespace needed between tags
		if last == '>' && first == '<' {
			sb.WriteString(part)
			return
		}
		if last != '>' && last != ' ' && first != '<' && first != '>' {
			sb.WriteByte(' ')
		}
	}
	sb.WriteString(part)
}

// formatXMLSingleLine collapses XML/SVG whitespace into a single line while preserving all comments.
func formatXMLSingleLine(xml []byte) []byte {
	if len(xml) == 0 {
		return nil
	}
	lines := strings.Split(string(xml), "\n")
	var sb strings.Builder
	sb.Grow(len(xml))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if sb.Len() > 0 {
			last := sb.String()[sb.Len()-1]
			first := trimmed[0]
			if last == '>' && first == '<' {
				sb.WriteString(trimmed)
				continue
			}
			if last != ' ' && first != ' ' {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(trimmed)
	}
	return bytes.TrimSpace([]byte(sb.String()))
}
