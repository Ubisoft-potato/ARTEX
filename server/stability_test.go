package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestStabilityFinalPlannerUnavailableIsBounded(t *testing.T) {
	e := NewEngine(&Manager{})
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	start := time.Now()
	if e.runFinalPlannerRound(ctx, &Task{ID: "missing-provider"}) {
		t.Fatal("unavailable planner proved the goal")
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatalf("waited for outer shutdown: %s", elapsed)
	}
	if ctx.Err() != nil {
		t.Fatal("exhausted the service deadline")
	}
}

func TestStabilitySettlementRetriesOnlyCommit(t *testing.T) {
	var attempts int
	if err := retrySettlement(context.Background(), func(ctx context.Context) error {
		attempts++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded database write")
		}
		if attempts < 3 {
			return errors.New("temporary database failure")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatal(attempts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := retrySettlement(ctx, func(context.Context) error { return errors.New("offline") }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestStabilityReceiptIsDurableAndRecoverable(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skip("isolated PostgreSQL not configured")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("receipt recovery", "goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.pg.Exec(`DELETE FROM tasks WHERE exploration_id=$1`, task.ExpID)
		m.pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExpID)
	})
	id, err := task.Store.AddNode("intent", map[string]any{"summary": "do once"}, 0, "open", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := task.Store.StartIntentExecution(context.Background(), id, "open", "w", "one"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	r := settlementReceipt{TaskID: task.ID, ExplorationID: task.ExpID, IntentID: id, Token: "one", State: "done"}
	path, err := writeSettlement(filepath.Join(m.dir, ".settlements", task.ID), r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved settlementReceipt
	if err := json.Unmarshal(b, &saved); err != nil || saved.Token != "one" {
		t.Fatal(saved, err)
	}
	e := NewEngine(m)
	if err := e.recoverSettlements(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	n, err := task.Store.GetNode(id)
	if err != nil || n.State != "done" {
		t.Fatal(n, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("receipt was not retired", err)
	}
}

func TestStabilityBroadcastOverflowDisconnectsBeforeCursorGap(t *testing.T) {
	b := NewBroadcaster()
	ch, unsubscribe := b.Subscribe("task")
	defer unsubscribe()
	for i := int64(1); i <= 257; i++ {
		b.Publish("task", db.Activity{ID: i})
	}
	b.Publish("task", db.Activity{ID: 258})
	var last int64
	for item := range ch {
		if item.ID != last+1 {
			t.Fatal("advanced over lost event")
		}
		last = item.ID
	}
	if last != 256 {
		t.Fatal(last)
	}
	unsubscribe()
}

func TestStabilityLogSubscriptionConcurrentClose(t *testing.T) {
	sink := &logSinkT{cap: 10, subs: map[chan LogLine]struct{}{}, out: io.Discard}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		_, closeSub := sink.subscribe()
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				sink.add(LogLine{Text: "event"})
			}
		}()
		go func() { defer wg.Done(); closeSub(); closeSub() }()
	}
	wg.Wait()
}

func TestStabilityShutdownWaitsForFinalBackgroundWrite(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	s := &Server{ctx: ctx, cancel: cancel, engine: NewEngine(nil), m: &Manager{}, chatBusy: map[string]bool{}, triggerActive: map[string]int{}}
	var finished atomic.Bool
	if !s.startBackground(func() { <-ctx.Done(); time.Sleep(25 * time.Millisecond); finished.Store(true) }) {
		t.Fatal("registration rejected")
	}
	deadline, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.Shutdown(deadline); err != nil {
		t.Fatal(err)
	}
	if !finished.Load() {
		t.Fatal("stores could close before final write")
	}
	if s.startBackground(func() { t.Error("admitted after shutdown") }) {
		t.Fatal("accepted new work")
	}
}

func TestStabilityStreamReadsCommittedOrderDespitePublishOrder(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skip("isolated PostgreSQL not configured")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("stream order", "goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		m.pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExpID)
	})
	s := &Server{m: m, ctx: context.Background(), engine: NewEngine(m)}
	srv := httptest.NewServer(http.HandlerFunc(s.streamActivity))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"?task="+task.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first, err := task.Store.AppendActivity(db.Activity{Kind: "text", Summary: "first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := task.Store.AppendActivity(db.Activity{Kind: "text", Summary: "second"})
	if err != nil {
		t.Fatal(err)
	}
	s.engine.Broadcaster().Publish(task.ID, db.Activity{ID: second})
	s.engine.Broadcaster().Publish(task.ID, db.Activity{ID: first})
	scanner := bufio.NewScanner(resp.Body)
	var got []int64
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "id: ") {
			n, err := strconv.ParseInt(strings.TrimPrefix(line, "id: "), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, n)
			if len(got) == 2 {
				break
			}
		}
	}
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("stream advanced past committed row: %v (%v)", got, scanner.Err())
	}
}

func TestStabilityOldTaskReceiptCannotFinishRevivedTask(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skip("isolated PostgreSQL not configured")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("run revision", "goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		m.pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExpID)
	})
	e := NewEngine(m)
	old := settlementReceipt{TaskID: task.ID, ExplorationID: task.ExpID, State: "done"}
	if err := e.applySettlement(context.Background(), task, old); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	if task.lifecycleSnapshot().RunRevision != 1 {
		t.Fatal("run generation not advanced")
	}
	if err := e.applySettlement(context.Background(), task, old); !errors.Is(err, db.ErrIntentStateConflict) {
		t.Fatal("old receipt applied to new run", err)
	}
	if m.TaskStatus(task.ID) != "running" {
		t.Fatal("revived task was completed by old receipt")
	}
}
