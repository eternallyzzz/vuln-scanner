package server

import (
	"testing"

	"vuln-scanner/internal/store"
)

func TestReportReconcilePlanAddUpdateRemove(t *testing.T) {
	report := func(id int64, enabled bool, schedule string, to ...string) store.TenantReport {
		return store.TenantReport{
			TenantID: id,
			Enabled:  enabled,
			Schedule: schedule,
			Timezone: "Local",
			To:       to,
		}
	}

	current := map[int64]store.TenantReport{
		1: report(1, true, "0 8 * * *", "a@example.com"),
		2: report(2, true, "0 8 * * *", "b@example.com"),
		3: report(3, true, "0 8 * * *", "c@example.com"),
		4: report(4, true, "0 8 * * *", "d@example.com"),
		5: report(5, true, "0 8 * * *", "e@example.com"),
	}
	reports := []store.TenantReport{
		report(1, true, "0 9 * * *", "a@example.com"),  // schedule change -> update
		report(2, true, "0 8 * * *", "b2@example.com"), // recipients change -> update
		report(3, true, "0 8 * * *", "c@example.com"),  // unchanged -> nothing
		report(4, false, "0 8 * * *", "d@example.com"), // disabled -> remove
		report(5, true, "0 8 * * *"),                   // no recipients -> remove
		report(6, true, "0 7 * * *", "f@example.com"),  // new -> add
	}

	add, update, remove := reportReconcilePlan(current, reports)
	if len(add) != 1 || add[0].TenantID != 6 {
		t.Fatalf("add = %#v, want tenant 6 only", add)
	}
	if len(update) != 2 || update[0].TenantID != 1 || update[1].TenantID != 2 {
		t.Fatalf("update = %#v, want tenants 1 and 2", update)
	}
	if len(remove) != 2 || remove[0] != 4 || remove[1] != 5 {
		t.Fatalf("remove = %#v, want tenants 4 and 5", remove)
	}
}

func TestReportReconcilePlanDeletedTenant(t *testing.T) {
	current := map[int64]store.TenantReport{
		9: {TenantID: 9, Enabled: true, Schedule: "0 8 * * *", Timezone: "Local", To: []string{"x@example.com"}},
	}
	add, update, remove := reportReconcilePlan(current, nil)
	if len(add) != 0 || len(update) != 0 || len(remove) != 1 || remove[0] != 9 {
		t.Fatalf("deleted tenant plan = add %#v update %#v remove %#v, want remove 9", add, update, remove)
	}
}

func TestReportSettingsEqualRecipientsAsSet(t *testing.T) {
	a := store.TenantReport{Enabled: true, Schedule: "0 8 * * *", Timezone: "Local",
		To: []string{"a@example.com", "b@example.com"}}
	b := store.TenantReport{Enabled: true, Schedule: "0 8 * * *", Timezone: "Local",
		To: []string{"b@example.com", "a@example.com"}}
	if !reportSettingsEqual(a, b) {
		t.Fatal("recipient order should not trigger a cron replacement")
	}
	b.To = []string{"a@example.com", "a@example.com"}
	if reportSettingsEqual(a, b) {
		t.Fatal("different recipient multiset must trigger a cron replacement")
	}
}
