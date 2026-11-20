# DDoS response runbook

## Confirm the incident

1. Open the incident for the customer you are assisting. Check the tenant
   indicator and the protected prefix before reviewing any traffic or
   decision. Open **Show original traffic evidence**.
2. Record the vector, its confidence, and the two completed observation
   windows. Use **Open DDoS incident report** for the highest window-average
   bit and packet rates, the observed duration, and the leading observed
   source addresses. Export the typed report through the incident CLI if
   you need to retain it with the customer's case.
3. Check source coverage and sampling before comparing rates with device
   counters. The report's source addresses describe observations from
   the selected view. A reflector association alone cannot establish
   who originated the activity.

## Review a response

1. In the traffic receipt, select **Prepare routing proposal**. Choose the
   configured routing context and protected prefix, an unfiltered
   whole-prefix flow view, and a known benign source prefix. Use the
   context's agreed RTBH community or an exact FlowSpec match.
2. Preview the collateral. For FlowSpec, compare **Whole protected
   prefix** with **Traffic matching the proposal**. Confirm the known
   benign packet count, the unclassified portion, and the proposed
   address scope. Set the maximum that this response is allowed to affect.
3. File the exact preview. A different active tenant account opens the
   review under **Admin → AI remediation proposals**. For a FlowSpec
   review, check the device's documented profile and its reported free
   entries before accepting the proposed rule. Record the approval from
   that interactive session.
4. Carry the approved plan into the customer's established network
   change process. Record the device or provider acknowledgement and
   the time it was observed. Use those observations to distinguish an
   approved plan, a route accepted in the control plane and an active
   forwarding action.

## Close and retain evidence

1. Confirm removal through the same authorized route or provider scope.
   Record the observed removal time and check that related traffic and
   service signals recovered.
2. Retain the exact report and recorded approvals in the customer's
   incident record. If the collector or source view was unavailable,
   record the coverage gap and the last complete observation time.
3. Review the benign packet limit and detection policy with the customer
   after the incident, using the recorded observations and phase changes.
