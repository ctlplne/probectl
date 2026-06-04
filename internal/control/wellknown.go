package control

import (
	"fmt"
	"net/http"
	"time"
)

// defaultSecurityContact is advertised when the operator has not configured one.
// It points at the disclosure policy rather than a fake mailbox.
const defaultSecurityContact = "https://github.com/imfeelingtheagi/probectl/blob/main/SECURITY.md"

// handleSecurityTxt serves an RFC 9116 security.txt advertising this deployment's
// vulnerability-disclosure contact (operator-set via PROBECTL_SECURITY_CONTACT) and
// the disclosure policy. Expires is always a year out so the file stays valid.
// Public — no authentication.
func (s *Server) handleSecurityTxt(w http.ResponseWriter, _ *http.Request) error {
	contact := s.cfg.SecurityContact
	if contact == "" {
		contact = defaultSecurityContact
	}
	expires := time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339)
	body := fmt.Sprintf(
		"# probectl vulnerability disclosure (RFC 9116).\n"+
			"# Set PROBECTL_SECURITY_CONTACT to your security mailbox for this deployment.\n"+
			"Contact: %s\n"+
			"Expires: %s\n"+
			"Preferred-Languages: en\n"+
			"Policy: https://github.com/imfeelingtheagi/probectl/blob/main/SECURITY.md\n",
		contact, expires)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=86400")
	_, _ = w.Write([]byte(body))
	return nil
}
