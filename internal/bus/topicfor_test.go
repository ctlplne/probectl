package bus

import "testing"

func TestTopicFor(t *testing.T) {
	ok := []struct{ ns, base, want string }{
		{"", NetworkResultsTopic, "probectl.network.results"},
		{"t-acme", NetworkResultsTopic, "probectl.t-acme.network.results"},
		{"t-acme", RUMEventsTopic, "probectl.t-acme.rum.events"},
		{"t-acme", FlowEventsTopic, "probectl.t-acme.flow.events"},
	}
	for _, c := range ok {
		got, err := TopicFor(c.ns, c.base)
		if err != nil || got != c.want {
			t.Errorf("TopicFor(%q,%q) = %q,%v, want %q", c.ns, c.base, got, err, c.want)
		}
	}
	// RED-006 (fail closed): an INVALID non-empty namespace is an error —
	// never a silent fallback onto the shared lane. Same for a base topic
	// that cannot be namespaced.
	bad := []struct{ ns, base string }{
		{"Bad.Namespace", NetworkResultsTopic},
		{"UPPER", NetworkResultsTopic},
		{"-lead", NetworkResultsTopic},
		{"t-acme", "other.topic"},
	}
	for _, c := range bad {
		if got, err := TopicFor(c.ns, c.base); err == nil {
			t.Errorf("TopicFor(%q,%q) = %q, want error (fail closed, RED-006)", c.ns, c.base, got)
		}
	}
	if !ValidNamespace("") || !ValidNamespace("t-acme-2") {
		t.Fatal("valid namespaces rejected")
	}
	if ValidNamespace("has.dot") || ValidNamespace("-lead") || ValidNamespace("UP") {
		t.Fatal("invalid namespaces accepted")
	}
}
