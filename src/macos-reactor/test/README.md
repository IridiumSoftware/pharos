# PharOS macos-reactor test fixtures (PH-019)

This directory holds the test harness for PH-019 MVP-1. The harness
is staged but not yet wired into CI — macOS event-stream tests have
no portable CI surface (the GitHub `macos-latest` runner doesn't
expose `log stream` semantics reliably).

## Files

- `test_lavalamp_client.py` — unit tests for the LL-043 v4 protocol
  consumer. Uses a Python AF_UNIX mock daemon that signs responses
  with a known private key. Runs on any macOS or Linux host with
  `python3-ecdsa` installed.
- `test_reactions_dry_run.py` — smoke test that exercises every
  reaction primitive in `--dry-run` mode and asserts no subprocess
  side effects.
- `test_reactor_pipeline.py` — end-to-end test of the
  log-stream → reactor → mock-daemon → reaction pipeline. Injects
  synthetic auth-event lines through an iterator instead of a real
  `log stream` subprocess. macOS-only (the reaction primitives shell
  out to `pmset` / `launchctl`).

## Running locally

```sh
cd src/macos-reactor
python3 -m unittest discover -s test -v
```

## Promotion path

PH-019 → `:tested` requires:

1. All three tests above pass on the developer's macOS host.
2. A scripted live fixture that:
   - Starts a real LavaLamp daemon in a controlled mode.
   - Loads the reactor with `--dry-run` in foreground.
   - Triggers a real `sudo` command.
   - Asserts the reactor observes the auth event and runs the verify
     pipeline within a wall-clock budget.
   - Flips the daemon to a REJECT-cached state.
   - Triggers a second `sudo`.
   - Asserts the reactor's reaction dispatcher fires within budget.

Once that fixture passes, PH-019 MVP-1 lifts from `:open` to
`:tested`. MVP-2 (`:tested` upgrade with ES entitlement) requires
porting the event-source backend to Swift and re-running the same
fixture against the ES client.
