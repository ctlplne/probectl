package bus

import "testing"

func TestTopicFor(t *testing.T) {
	cases := []struct{ ns, base, want string }{
		{"", NetworkResultsTopic, "probectl.network.results"},
		{"t-acme", NetworkResultsTopic, "probectl.t-acme.network.results"},
		{"t-acme", RUMEventsTopic, "probectl.t-acme.rum.events"},
		{"t-acme", FlowEventsTopic, "probectl.t-acme.flow.events"},
		// Invalid namespaces degrade to the shared lane (the namespace is a
		// delivery lane, never the tenant boundary).
		{"Bad.Namespace", NetworkResultsTopic, "probectl.network.results"},
		{"UPPER", NetworkResultsTopic, "probectl.network.results"},
		// A non-probectl base is returned unchanged.
		{"t-acme", "other.topic", "other.topic"},
	}
	for _, c := range cases {
		if got := TopicFor(c.ns, c.base); got != c.want {
			t.Errorf("TopicFor(%q,%q) = %q, want %q", c.ns, c.base, got, c.want)
		}
	}
	if !ValidNamespace("") || !ValidNamespace("t-acme-2") {
		t.Fatal("valid namespaces rejected")
	}
	if ValidNamespace("has.dot") || ValidNamespace("-lead") || ValidNamespace("UP") {
		t.Fatal("invalid namespaces accepted")
	}
}
