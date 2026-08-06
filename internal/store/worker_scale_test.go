package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// testWorkerScaleDB returns a store backed by VULNSCAN_TEST_DATABASE_URL.
// These tests exercise real PostgreSQL queue/lease semantics and are skipped
// unless the environment variable is set (CI/unit runs stay DB-free).
func testWorkerScaleDB(t *testing.T) *Store {
	url := os.Getenv("VULNSCAN_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("VULNSCAN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RunMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestWorkerScaleLeases(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()

	ok1, err := s.AcquireLoopLease(ctx, "test-loop", "w1", "h1", 1, time.Minute)
	if err != nil || !ok1 {
		t.Fatalf("first acquire = %v,%v want true,nil", ok1, err)
	}
	ok2, err := s.AcquireLoopLease(ctx, "test-loop", "w2", "h2", 2, time.Minute)
	if err != nil || ok2 {
		t.Fatalf("second acquire = %v,%v want false,nil while held", ok2, err)
	}
	renewed, err := s.RenewLoopLease(ctx, "test-loop", "w1", time.Minute)
	if err != nil || !renewed {
		t.Fatalf("renew = %v,%v want true,nil", renewed, err)
	}
	if err := s.ReleaseLoopLease(ctx, "test-loop", "w1"); err != nil {
		t.Fatal(err)
	}
	ok3, err := s.AcquireLoopLease(ctx, "test-loop", "w2", "h2", 2, time.Minute)
	if err != nil || !ok3 {
		t.Fatalf("acquire after release = %v,%v want true,nil", ok3, err)
	}
	if err := s.ReleaseLoopLease(ctx, "test-loop", "w2"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.AcquireLoopLease(ctx, "test-expire", "w1", "h1", 1, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	ok4, err := s.AcquireLoopLease(ctx, "test-expire", "w2", "h2", 2, time.Minute)
	if err != nil || !ok4 {
		t.Fatalf("expired lease takeover = %v,%v want true,nil", ok4, err)
	}
	if err := s.ReleaseLoopLease(ctx, "test-expire", "w2"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerScaleJobsAndState(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()

	id, inserted, err := s.EnqueueJob(ctx, "test-kind", "k1", map[string]interface{}{"a": 1})
	if err != nil || !inserted || id == 0 {
		t.Fatalf("enqueue = %d,%v,%v want inserted with id", id, inserted, err)
	}
	if _, inserted2, err := s.EnqueueJob(ctx, "test-kind", "k1", nil); err != nil || inserted2 {
		t.Fatalf("duplicate live job = %v,%v want not inserted", inserted2, err)
	}
	jobs, err := s.ClaimJobs(ctx, []string{"test-kind"}, "w1", 10)
	if err != nil || len(jobs) != 1 || jobs[0].ClaimedBy != "w1" {
		t.Fatalf("claim = %d jobs err %v, want 1 claimed by w1", len(jobs), err)
	}
	if jobs2, _ := s.ClaimJobs(ctx, []string{"test-kind"}, "w2", 10); len(jobs2) != 0 {
		t.Fatal("second worker claimed an already claimed job")
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE job_queue SET claimed_at=NOW() - interval '3 minutes' WHERE id=$1`, jobs[0].ID); err != nil {
		t.Fatal(err)
	}
	n, err := s.RequeueStaleJobs(ctx, 2*time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("requeue stale = %d,%v want 1", n, err)
	}
	jobs2, err := s.ClaimJobs(ctx, []string{"test-kind"}, "w2", 10)
	if err != nil || len(jobs2) != 1 {
		t.Fatalf("reclaim after requeue = %d,%v want 1", len(jobs2), err)
	}
	if err := s.FinishJob(ctx, jobs2[0].ID, "boom"); err != nil {
		t.Fatal(err)
	}
	counts, err := s.PendingJobCounts(ctx)
	if err != nil || counts["test-kind"] != 0 {
		t.Fatalf("pending counts = %v,%v want test-kind 0", counts, err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM job_queue WHERE kind='test-kind'`); err != nil {
		t.Fatal(err)
	}

	if err := s.SetWorkerState(ctx, "feed_ready", true); err != nil {
		t.Fatal(err)
	}
	ready, err := s.GetWorkerStateBool(ctx, "feed_ready")
	if err != nil || !ready {
		t.Fatalf("feed_ready = %v,%v want true,nil", ready, err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM worker_state WHERE key='feed_ready'`); err != nil {
		t.Fatal(err)
	}
}
