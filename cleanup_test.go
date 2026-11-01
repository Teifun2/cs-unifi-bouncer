package main

import (
	"testing"
	"time"
)

func TestCleanupWindowOverlaps(t *testing.T) {
	now := time.Now()
	from, to := cleanupWindow(now, time.Time{}, 30)
	if to != now.UnixMilli() || from != now.Add(-startupCleanupLookback).UnixMilli() {
		t.Fatalf("unexpected window %d-%d", from, to)
	}
	from, _ = cleanupWindow(now, now.Add(-30*time.Minute), 30)
	if from != now.Add(-60*time.Minute).UnixMilli() {
		t.Fatalf("unexpected from %d", from)
	}
	// previous run 30m ago must be fully covered by the next window
	prevTo := now.Add(-30 * time.Minute).UnixMilli()
	if from > prevTo {
		t.Fatal("windows do not overlap")
	}
	// after failures, window reaches back to last success
	from, _ = cleanupWindow(now, now.Add(-3*time.Hour), 30)
	if from != now.Add(-3*time.Hour-30*time.Minute).UnixMilli() {
		t.Fatalf("unexpected from %d", from)
	}
}
