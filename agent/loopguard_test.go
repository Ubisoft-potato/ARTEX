package agent

import "testing"

func TestToolLoopGuardTripsOnIdenticalCalls(t *testing.T) {
	var g toolLoopGuard
	input := []byte(`{"todos":[{"content":"same","status":"pending"}]}`)
	sig := g.remember("TodoWrite", input)
	result := []byte("todos updated")

	for i := 1; i < maxIdenticalToolCalls; i++ {
		if g.observeResult("TodoWrite", sig, result) {
			t.Fatalf("tripped after %d identical calls, want %d", i, maxIdenticalToolCalls)
		}
	}
	if !g.observeResult("TodoWrite", sig, result) {
		t.Fatalf("did not trip after %d identical calls", maxIdenticalToolCalls)
	}
}

func TestToolLoopGuardResetsOnDifferentInput(t *testing.T) {
	var g toolLoopGuard
	a := g.remember("TodoWrite", []byte(`{"x":1}`))
	b := g.remember("TodoWrite", []byte(`{"x":2}`))
	result := []byte("ok")

	g.observeResult("TodoWrite", a, result)
	g.observeResult("TodoWrite", a, result)
	if g.observeResult("TodoWrite", b, result) {
		t.Fatal("different input must reset the streak")
	}
	if g.observeResult("TodoWrite", b, result) {
		t.Fatal("tripped too early after reset")
	}
	if g.observeResult("TodoWrite", b, result) {
		t.Fatal("tripped too early after reset")
	}
	if !g.observeResult("TodoWrite", b, result) {
		t.Fatalf("did not trip after %d identical calls following a reset", maxIdenticalToolCalls)
	}
}

func TestToolLoopGuardSeparatesTools(t *testing.T) {
	var g toolLoopGuard
	input := []byte(`{"same":"input"}`)
	result := []byte("ok")

	for i := 1; i < maxIdenticalToolCalls; i++ {
		g.observeResult("Read", g.remember("Read", input), result)
	}
	if g.observeResult("Bash", g.remember("Bash", input), result) {
		t.Fatal("a different tool name must reset the streak")
	}
}

func TestToolLoopGuardAllowsChangingResults(t *testing.T) {
	var g toolLoopGuard
	input := []byte(`{"command":"curl -s http://target"}`)
	sig := g.remember("Bash", input)

	for i := 0; i < maxIdenticalPollCalls+2; i++ {
		if g.observeResult("Bash", sig, []byte{'r', byte('0' + i)}) {
			t.Fatal("same command with a changing/current result must not trip")
		}
	}
}

func TestToolLoopGuardAllowsPassivePollingCycle(t *testing.T) {
	var g toolLoopGuard
	sleep := g.remember("sleep", []byte(`{"seconds":20}`))
	read := g.remember("shell_read", []byte(`{"session_id":"sh_1"}`))
	sleepResult := []byte("slept 20s")
	readResult := []byte("still running")

	// A monitor naturally cycles sleep -> shell_read many times with unchanged
	// output. This must not be mistaken for a reasoning loop.
	for i := 0; i < loopCycleRepeats+3; i++ {
		if g.observeResult("sleep", sleep, sleepResult) {
			t.Fatalf("sleep/read monitor tripped on sleep iteration %d", i)
		}
		if g.observeResult("shell_read", read, readResult) {
			t.Fatalf("sleep/read monitor tripped on read iteration %d", i)
		}
	}
}

func TestToolLoopGuardTripsOnBashPolling(t *testing.T) {
	var g toolLoopGuard
	input := []byte(`{"command":"curl -s -o /dev/null -w '%{http_code}' http://target"}`)
	sig := g.remember("Bash", input)
	result := []byte("000")

	for i := 1; i < maxIdenticalPollCalls; i++ {
		if g.observeResult("Bash", sig, result) {
			t.Fatalf("Bash polling tripped after %d identical calls, want %d", i, maxIdenticalPollCalls)
		}
	}
	if !g.observeResult("Bash", sig, result) {
		t.Fatalf("Bash polling did not trip after %d identical calls", maxIdenticalPollCalls)
	}
}

func TestToolLoopGuardDetectsAlternatingCycle(t *testing.T) {
	var g toolLoopGuard
	a := g.remember("TodoWrite", []byte(`{"todos":[{"content":"a"}]}`))
	b := g.remember("TodoWrite", []byte(`{"todos":[{"content":"b"}]}`))
	result := []byte("ok")

	for i := 0; i < loopCycleRepeats; i++ {
		if g.observeResult("TodoWrite", a, result) {
			t.Fatalf("tripped on cycle repetition %d (a)", i)
		}
		if g.observeResult("TodoWrite", b, result) {
			return // expected: the third b completes the A/B/A/B/A/B cycle
		}
	}
	t.Fatal("did not detect an A/B/A/B/A/B cycle")
}

func TestCanonicalToolInputNormalisesJSON(t *testing.T) {
	a := canonicalToolInput([]byte(`{"b":2,"a":1}`))
	b := canonicalToolInput([]byte("{\n  \"a\": 1,\n  \"b\": 2\n}"))
	if string(a) != string(b) {
		t.Fatalf("canonical JSON differs: %s vs %s", a, b)
	}
	if sigA, sigB := hashToolParts(a), hashToolParts(b); sigA != sigB {
		t.Fatal("canonical JSON must hash identically")
	}
}
