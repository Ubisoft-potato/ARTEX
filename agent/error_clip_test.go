package agent

import (
	"strings"
	"testing"
)

func TestClipErrorTextShortUnchanged(t *testing.T) {
	const msg = "openai: status 530: tunnel unavailable"
	if got := ClipErrorText("  " + msg + "\n"); got != msg {
		t.Fatalf("ClipErrorText()=%q, want %q", got, msg)
	}
}

func TestClipErrorTextBoundsHugeBody(t *testing.T) {
	body := "openai: status 530: <html><title>Cloudflare Tunnel error</title>" + strings.Repeat("x", 32<<10)
	got := ClipErrorText(body)
	if len(got) > maxErrorTextBytes+64 {
		t.Fatalf("clipped error is %d bytes, want <= %d", len(got), maxErrorTextBytes+64)
	}
	if !strings.Contains(got, "截断") {
		t.Fatalf("clipped error must mark truncation: %q", got)
	}
	if !strings.HasPrefix(got, "openai: status 530") {
		t.Fatalf("clipped error lost useful prefix: %q", got)
	}
}

func TestClipErrorTextEmpty(t *testing.T) {
	if got := ClipErrorText(" \n\t "); got != "(空错误)" {
		t.Fatalf("ClipErrorText(empty)=%q", got)
	}
}
