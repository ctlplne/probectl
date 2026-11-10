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
