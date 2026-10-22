package agent

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
)

var (
	// ErrToolLoop marks a run aborted because the model kept issuing the same
	// tool call with the same result (a degenerate loop). The engine treats it
	// as a recoverable round failure and logs it distinctly, so a recurring
	// model/prompt problem is visible instead of looking like a provider error.
	ErrToolLoop = errors.New("agent: repeated identical tool call; aborted to break a loop")
	// ErrRunIdle marks a run whose model stream produced no event for too long.
	// It is a recoverable run failure, not a user cancellation.
	ErrRunIdle = errors.New("agent: model stream idle timeout; aborted to avoid a hang")
)

const (
	// maxIdenticalToolCalls is how many identical completed calls (same tool,
	// input AND result) are tolerated before cutting the run. Legitimate polling
	// whose output changes does not count; the 2026-10-22 incident repeated one
	// TodoWrite 78 times with an unchanged acknowledgement.
	maxIdenticalToolCalls = 4
	// loopCycleWindow/loopCycleRepeats catch alternating A/B/A/B (or A/B/C)
	// loops that never become four consecutive identical calls.
	loopCycleWindow  = 12
	loopCycleRepeats = 3
)

// toolCallSig identifies one completed tool call. The result hash is important:
// a worker legitimately retrying `curl` while a service starts produces the
// same input but different output, and must not be mistaken for a loop.
type toolCallSig struct {
	name   string
	input  [sha256.Size]byte
	result [sha256.Size]byte
}

// toolLoopGuard tracks the recent completed calls for one run. It is pure and
// per-run, so planner and worker get the same protection regardless of the tools
// the SDK injected.
type toolLoopGuard struct {
	last   toolCallSig
	repeat int
	recent []toolCallSig
}

func hashToolParts(parts ...[]byte) [sha256.Size]byte {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		_, _ = h.Write(p)
	}
	var sig [sha256.Size]byte
	copy(sig[:], h.Sum(nil))
	return sig
}

// canonicalToolInput normalises JSON key order/whitespace so the same semantic
// call is recognised even when the model serialises it differently.
func canonicalToolInput(input []byte) []byte {
	if len(input) == 0 || !json.Valid(input) {
		return input
	}
	var v any
	if err := json.Unmarshal(input, &v); err != nil {
		return input
	}
	b, err := json.Marshal(v)
	if err != nil {
		return input
	}
	return b
}

// remember records a tool_use's name + canonical input. The returned signature
// is held until the matching tool_result arrives; remember itself never trips.
func (g *toolLoopGuard) remember(name string, input []byte) [sha256.Size]byte {
	return hashToolParts([]byte(name), canonicalToolInput(input))
}

// observeResult records a completed call and reports whether the run has
// degenerated into a loop. A different input, result or tool resets the
// consecutive streak; a repeated cycle of 2..4 calls is also detected.
func (g *toolLoopGuard) observeResult(name string, inputSig [sha256.Size]byte, result []byte) bool {
	sig := toolCallSig{name: name, input: inputSig, result: hashToolParts(result)}
	if g.repeat > 0 && g.last.name == sig.name && g.last.input == sig.input && g.last.result == sig.result {
		g.repeat++
	} else {
		g.repeat = 1
	}
	g.last = sig
	g.recent = append(g.recent, sig)
	if len(g.recent) > loopCycleWindow {
		g.recent = g.recent[len(g.recent)-loopCycleWindow:]
	}
	if g.repeat >= maxIdenticalToolCalls {
		return true
	}
	// A/B/A/B/A/B (and A/B/C repeated three times) are loops too, even though
	// no call is byte-identical to its immediate predecessor.
	for n := 2; n <= 4; n++ {
		if len(g.recent) < n*loopCycleRepeats {
			continue
		}
		tail := g.recent[len(g.recent)-n*loopCycleRepeats:]
		ok := true
		for i := range tail {
			if tail[i] != tail[i%n] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
