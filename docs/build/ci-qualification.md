# Complete CI qualification

The `ci` workflow runs all its standing checks on a main push or pull request.
Development runs can be superseded; a cancelled, skipped or unexecuted required
check remains unverified. A compile or image-build pass alone is insufficient.

For a feature checkpoint or final qualification, dispatch the same complete
workflow on the exact current main SHA:

```sh
git fetch origin main
candidate=$(git rev-parse origin/main)
gh workflow run ci.yml --ref main -f qualification_sha="$candidate"
gh run list --workflow ci.yml --event workflow_dispatch --commit "$candidate"
```

If main moves before GitHub dispatches the request, the pin check fails rather
than qualifying a different commit. Capture the new candidate and dispatch
again. After dispatch, every checkout uses that run's immutable event SHA.
Manual qualification has its own concurrency group, including while queued;
later pushes cannot replace it. Keep the candidate on main when collecting the
final acceptance evidence, and allow the whole qualification to finish.

The `ci-qualification-<run-id>-<attempt>` artifact records the event, exact
checkout SHA, mode and run identity. `verify-all` still requires every existing
verification job. Release and item closure require complete successful CI on
the exact pushed main SHA together with their original item-specific evidence.
Security and CodeQL continue on every push and remain independent of development
coalescing. This workflow does not publish an image, release or tag.

`ci-development` receives CI-start metadata and executes only the trusted
default-branch checkout. Once the source run's existing `action-pins` validation
succeeds, it can request normal cancellation of older first-attempt `ci.yml`
main pushes whose SHA is a verified ancestor. It excludes manual qualification,
reruns, tags, schedules, releases, foreign repositories and other workflows.
An active protected run's SHA is also excluded. Security-scan and CodeQL retain
their independent runs on every push.

The `ci-development-<run-id>-<attempt>` artifact retains cancellation receipts,
pre-cancellation job conclusions, artifact identities and run links for 90 days.
Cancellation does not delete GitHub's existing logs or artifacts and does not
create evidence for steps that never ran. Required incomplete checks remain owed
to the complete pinned qualification.

The existing typecheck, production bundle, bundle budget and real control-plane
UI-embed compile run early in `web-build`. Image matrices and release-image E2E
also wait for the existing release/dev-auth compile checks. Frontend audits,
lint, complete coverage and both-theme rendered accessibility remain required;
their independent jobs can continue while early builds execute. The early
untagged control binary is not substituted for a core/EE or FIPS image.

Each image producer exports the existing complete amd64+arm64 build as OCI and
exports the cached amd64 result as a single-platform Docker archive. Both use
the exact commit, edition and source clock. `ci_image.py` verifies both platform
configs and layer descriptors, retains the OCI index and provenance, and
requires the Docker config digest to equal the multiarch amd64 config digest.
The second export reuses that job's builder cache; scanners and E2E do not build
another image.

The amd64 archive and receipt stay in this workflow run's `image-<component>-<sha>`
artifact for seven days. Scan and compatible production-auth E2E jobs verify
the full archive hash, source, edition, component and run before Docker load,
then check the loaded image ID/platform and tag that exact ID. All image scan
rows, their blocking severities and the browser worker's functional smoke proof
remain. Independent platform/provenance and consumer receipts last 90 days.
A Docker archive alone never qualifies multiarch support. An expired transfer
requires rerunning its producer; consumers never fetch a registry fallback.
