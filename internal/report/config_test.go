package report

import (
	"testing"
)

func TestConfigValidateDisabled(t *testing.T) {
	c := DefaultConfig()
	if err := c.Validate("", ""); err != nil {
		t.Fatalf("disabled reporting must validate without SMTP: %v", err)
	}
}

func TestConfigValidateNormalizesAndAccepts(t *testing.T) {
	c := &Config{
		Enabled:  true,
		Schedule: "",
		Timezone: "",
		To:       []string{"  ops@example.com ", ""},
	}
	if err := c.Validate("smtp.example.com", "reports@example.com"); err != nil {
		t.Fatal(err)
	}
	if c.Schedule != "0 8 * * *" || c.Timezone != "Local" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if len(c.To) != 1 || c.To[0] != "ops@example.com" {
		t.Fatalf("recipients not normalized: %#v", c.To)
	}
}

func TestConfigValidateErrors(t *testing.T) {
	base := func() *Config {
		return &Config{Enabled: true, To: []string{"ops@example.com"}}
	}
	badSchedule := base()
	badSchedule.Schedule = "not-a-cron"
	if err := badSchedule.Validate("smtp", "from@x"); err == nil {
		t.Fatal("invalid cron must be rejected")
	}

	badTZ := base()
	badTZ.Timezone = "Mars/Phobos"
	if err := badTZ.Validate("smtp", "from@x"); err == nil {
		t.Fatal("invalid timezone must be rejected")
	}

	noRecipients := base()
	noRecipients.To = nil
	if err := noRecipients.Validate("smtp", "from@x"); err == nil {
		t.Fatal("missing recipients must be rejected")
	}

	badRecipient := base()
	badRecipient.To = []string{"not-an-email"}
	if err := badRecipient.Validate("smtp", "from@x"); err == nil {
		t.Fatal("invalid recipient must be rejected")
	}

	noSMTP := base()
	if err := noSMTP.Validate("", "from@x"); err == nil {
		t.Fatal("missing SMTP host must be rejected")
	}
	noFrom := base()
	if err := noFrom.Validate("smtp", ""); err == nil {
		t.Fatal("missing SMTP from must be rejected")
	}
}

func TestConfigScheduleSpecAndLocation(t *testing.T) {
	c := &Config{}
	if got := c.ScheduleSpec(); got != "0 8 * * *" {
		t.Fatalf("ScheduleSpec() = %q, want default", got)
	}
	if _, err := c.Location(); err != nil {
		t.Fatalf("default location failed: %v", err)
	}
	c.Timezone = "UTC"
	if _, err := c.Location(); err != nil {
		t.Fatalf("UTC location failed: %v", err)
	}
}
