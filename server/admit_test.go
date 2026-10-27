package server

import "testing"

func TestHeadroomOK(t *testing.T) {
	const (
		mib = int64(1 << 20)
		gib = int64(1 << 30)
	)
	cases := []struct {
		name               string
		used, limit, avail int64
		cgOK, availOK      bool
		need               int64
		want               bool
	}{
		{
			name: "roomy", used: 1 * gib, limit: 4 * gib, avail: 2 * gib,
			cgOK: true, availOK: true, need: 256 * mib, want: true,
		},
		{
			name: "cgroup tight", used: 4*gib - 100*mib, limit: 4 * gib, avail: 2 * gib,
			cgOK: true, availOK: true, need: 256 * mib, want: false,
		},
		{
			name: "host tight", used: 1 * gib, limit: 4 * gib, avail: 700 * mib,
			cgOK: true, availOK: true, need: 256 * mib, want: false,
		},
		{
			name: "over limit", used: 5 * gib, limit: 4 * gib, avail: 2 * gib,
			cgOK: true, availOK: true, need: 256 * mib, want: false,
		},
		{
			name: "no cgroup, host roomy", avail: 2 * gib,
			cgOK: false, availOK: true, need: 600 * mib, want: true,
		},
		{
			name: "no cgroup, host tight", avail: 1 * gib,
			cgOK: false, availOK: true, need: 600 * mib, want: false, // 1G < 768M + 600M
		},
		{
			name: "unmeasurable", cgOK: false, availOK: false, need: 600 * mib, want: true,
		},
		{
			name: "browser headroom just short", used: 4*gib - 500*mib, limit: 4 * gib, avail: 2 * gib,
			cgOK: true, availOK: true, need: 600 * mib, want: false,
		},
		{
			name: "browser headroom just enough", used: 4*gib - 700*mib, limit: 4 * gib, avail: 2 * gib,
			cgOK: true, availOK: true, need: 600 * mib, want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := headroomOK(tc.used, tc.limit, tc.avail, tc.cgOK, tc.availOK, tc.need); got != tc.want {
				t.Fatalf("headroomOK = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAdmissionApplies(t *testing.T) {
	if admissionApplies("browser", "browser_close") {
		t.Fatal("browser_close must never be blocked: closing frees memory")
	}
	if !admissionApplies("browser", "browser_navigate") {
		t.Fatal("browser page operations must be gated")
	}
	if !admissionApplies("scopesentry", "query") {
		t.Fatal("other stdio MCP tools must be gated")
	}
}

func TestAdmissionEnabledEnv(t *testing.T) {
	t.Setenv("ARTEX_MEMGUARD", "")
	t.Setenv("ARTEX_MEMGUARD_ADMIT", "")
	if !admissionEnabled() {
		t.Fatal("admission must default to on")
	}
	t.Setenv("ARTEX_MEMGUARD_ADMIT", "off")
	if admissionEnabled() {
		t.Fatal("ARTEX_MEMGUARD_ADMIT=off must disable admission")
	}
	t.Setenv("ARTEX_MEMGUARD_ADMIT", "")
	t.Setenv("ARTEX_MEMGUARD", "off")
	if admissionEnabled() {
		t.Fatal("ARTEX_MEMGUARD=off must disable admission too")
	}
}

func TestShortToolName(t *testing.T) {
	if got := shortToolName("mcp__browser__browser_navigate"); got != "browser_navigate" {
		t.Fatalf("shortToolName = %q", got)
	}
	if got := shortToolName("plain"); got != "plain" {
		t.Fatalf("shortToolName = %q", got)
	}
}
