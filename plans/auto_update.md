# Plan: self-update for the Amallo client

Status: proposed, not implemented (as of 2026-08-04, on `v0.2.0`).

## Goal

Amallo checks GitHub for a newer release, and when one exists tells the user
about it in the tray and in Settings, offering a one-click "Install &
Restart". Updates are **never** installed without the user saying so — Amallo
holds a live relay socket, and an unannounced restart drops a paired web
client mid-stream.

## Approach: Tauri's built-in updater

Amallo is a Tauri v2 app, so `tauri-plugin-updater` is the answer rather than
anything hand-rolled. It gives us, for free, the parts that are actually hard
to get right: minisign signature verification of the downloaded bundle, the
NSIS/`.app` swap dance per platform, and version comparison. What we build is
the *policy* around it (when to check, how to surface it, when it's safe to
restart), not the mechanism.

The alternative — polling the GitHub releases API ourselves and opening a
browser to the download page — is less work up front but leaves the user doing
a manual reinstall every time, which for a background tray app means they
simply never update. Not worth it.

### Distribution assumption

The updater fetches `latest.json` and the bundle over plain HTTPS with **no
credentials**. `OpenCharUI/amallo` is currently private, and private release
assets are not reachable that way.

**This plan assumes the repo will be public at the time the updater ships.**
Do not flip visibility as part of this work — that's a separate decision. If
the repo stays private, everything below still holds except §2, which would
instead push bundles + `latest.json` to a public mirror repo
(`OpenCharUI/amallo-releases`) via a PAT, and §3's endpoint URL would point
there.

Note this is the right moment to do this work: `web` has no download link for
Amallo yet, so there are no installs in the wild that would be stranded
without an updater. Every future install gets one from day one.

---

## 1. Signing keys (one-time, do first)

```bash
npm run tauri signer generate -- -w ~/.tauri/amallo.key
```

- Private key + its password → GitHub repo secrets `TAURI_SIGNING_PRIVATE_KEY`
  and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
- Public key → `plugins.updater.pubkey` in `tauri.conf.json` (the key
  *content*, not a path).

> **Highest-consequence item in this plan.** The pubkey is baked into every
> shipped binary. Lose the private key and every existing install is
> permanently un-updatable — users would have to download and reinstall by
> hand to get back on a working channel. Back it up somewhere durable (a
> password manager entry, not just `~/.tauri`) before anything else.

These keys are unrelated to Apple code signing / notarization, which the
release workflow does not do today. That stays as-is: minisign covers update
integrity independently, and Gatekeeper friction on the *initial* download is
a separate problem.

---

## 2. Release pipeline (`.github/workflows/release.yml`)

The existing two-job shape (semantic-release → matrix build via
`tauri-action`) stays. Three changes:

1. **`bundle.createUpdaterArtifacts: true`** in `tauri.conf.json`. Produces
   `.app.tar.gz` + `.app.tar.gz.sig` on macOS and, alongside the NSIS
   installer, a `-setup.exe.sig` on Windows. Because the build is already
   NSIS-only on Windows (commit `6a99c50`), there's no WiX/NSIS ambiguity and
   `updaterJsonPreferNsis` doesn't need setting.

2. **Signing env on the build job:**

   ```yaml
   - name: Build and upload to the release
     uses: tauri-apps/tauri-action@v0
     env:
       GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
       TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
       TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
   ```

   `tauri-action`'s `uploadUpdaterJson` already defaults to `true`, so
   `latest.json` gets generated and attached to the release without any extra
   input.

3. **`max-parallel: 1` on the matrix.** This one is not optional and is easy
   to miss. `tauri-action` builds `latest.json` by *reading the existing
   `latest.json` asset off the release, merging its own platform entry in, and
   re-uploading* (`src/upload-version-json.ts`). With three legs running
   concurrently that's a read-modify-write race: two legs read the same
   baseline and the later upload silently drops the other's platform entry —
   producing a `latest.json` that, say, only has `windows-x86_64` and leaves
   every Mac user unable to see the update. Serializing the matrix costs
   wall-clock time on a release (three sequential builds), which is fine for
   something that runs a handful of times a month.

   ```yaml
   strategy:
     fail-fast: false
     max-parallel: 1
     matrix:
       ...
   ```

   If release wall time ever becomes a problem, the alternative is a fourth
   job that runs after the matrix and composes `latest.json` from the uploaded
   `.sig` assets in one shot — more code, but parallel.

Unrelated but worth fixing while in this file: the build step passes
`assetNamePattern`, but `tauri-action`'s actual input is
**`releaseAssetNamePattern`** — the current name isn't in the action's
`action.yml` and is being ignored. Asset naming doesn't affect the updater
(`latest.json` is generated from whatever was actually uploaded), so this is
cosmetic, but the `Amallo_[platform]_[arch]_[version][setup].[ext]` intent
from commits `6a99c50`/`38eb83d` is not currently taking effect.

**Resulting `latest.json`** (generated, not hand-written):

```json
{
  "version": "0.3.0",
  "notes": "…",
  "pub_date": "2026-08-04T…Z",
  "platforms": {
    "darwin-aarch64": { "signature": "…", "url": "https://api.github.com/repos/OpenCharUI/amallo/releases/assets/123" },
    "darwin-x86_64":  { "signature": "…", "url": "…" },
    "windows-x86_64": { "signature": "…", "url": "…" }
  }
}
```

The URLs are GitHub **API** asset URLs, not `browser_download_url`. These
return the binary only when the request carries
`Accept: application/octet-stream`, which the updater plugin sets — and they
resolve unauthenticated only for a public repo, which is the §0 assumption.

---

## 3. Client configuration

`src-tauri/tauri.conf.json`:

```json
"bundle": {
  "createUpdaterArtifacts": true
},
"plugins": {
  "updater": {
    "pubkey": "<content of ~/.tauri/amallo.key.pub>",
    "endpoints": [
      "https://github.com/OpenCharUI/amallo/releases/latest/download/latest.json"
    ],
    "windows": { "installMode": "passive" }
  }
}
```

- `installMode: "passive"` shows a progress bar with no prompts. `"quiet"`
  looks nicer but is more likely to be mistaken for a hang or blocked by
  UAC — `passive` is the safer default for a tray app the user isn't
  watching.
- No `{{target}}`/`{{arch}}`/`{{current_version}}` template variables needed:
  the static `latest.json` carries all platforms and the plugin picks the
  right one.

`src-tauri/Cargo.toml`:

```toml
tauri-plugin-updater = "2"
```

`src-tauri/capabilities/default.json` — add `"updater:default"`.

**No `tauri-plugin-process` and no `@tauri-apps/plugin-updater`.** The whole
flow is driven from Rust (see §4), so the frontend never calls the updater
directly and `app.restart()` covers relaunch without the process plugin or its
permission. This matches the existing shape of the codebase: 185 lines of
vanilla TS that only ever `invoke` commands and `listen` for events.

---

## 4. Rust: `src-tauri/src/update.rs` (new module)

Deliberately mirrors the existing `relay` + `RelayStatus` + tray-refresh
pattern, so it reads like the rest of the app.

**State** — add to `state.rs`, alongside `RelayStatus`:

```rust
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum UpdateStatus {
    Idle,                                            // never checked this session
    Checking,
    UpToDate,
    Available { version: String, notes: String, date: Option<String> },
    Downloading { percent: u8 },
    Ready { version: String },                       // staged; awaiting restart
    Error { message: String },
}
```

plus `pub update_status: RwLock<UpdateStatus>` on `AppState` and an
`update_status()` accessor, matching `relay_status()`.

**Module surface:**

- `set_status(app, UpdateStatus)` — writes state, `emit("update-status", …)`,
  calls `tray::refresh_update(app, &status)`. Same shape as
  `relay::set_status`.
- `check(app)` — `app.updater()?.check().await`. Sets `Available`/`UpToDate`/
  `Error`.
- `install(app)` — `download_and_install` with the progress callback mapped to
  `Downloading { percent }` (throttle emits to ~1/percent so we don't spam the
  webview), then `Ready`, then `app.restart()`.
- `spawn_periodic(app)` — background task: first check ~15s after launch (let
  the relay connect first; a failed update check should never be the reason
  the tray looks broken at startup), then every 6h. Gated on the new
  `auto_check_updates` setting.

**Registration** in `lib.rs`:

```rust
.plugin(tauri_plugin_updater::Builder::new()
    .on_before_exit(|| { /* close the relay socket cleanly */ })
    .build())
```

`on_before_exit` matters here specifically: on Windows the updater hands off
to the NSIS installer and terminates the process, which would otherwise drop
the relay WebSocket without a close frame and leave the relay holding a dead
pair until its ping timeout.

Note that `RunEvent::ExitRequested`'s `prevent_exit()` in `lib.rs` does not
block this — the updater's Windows path exits the process directly rather than
going through the Tauri event loop. Verify this explicitly during testing
(§7); if it *does* get blocked, the fix is to set a "restarting for update"
flag on `AppState` and let `ExitRequested` through when it's set.

**Error handling:** a failed check is normal (no network, GitHub blip, laptop
on a captive portal). It sets `Error` for the Settings card and is otherwise
silent — no dialog, no tray badge. Only a failed *install* is worth surfacing
prominently, since the user explicitly asked for it.

---

## 5. Commands & settings

`commands.rs` — three new handlers registered in `generate_handler!`:

- `get_update_status() -> UpdateStatus`
- `check_for_update()` — manual "Check now"; runs even when
  `auto_check_updates` is off.
- `install_update()` — the user pressed the button.
- `get_app_version() -> String` — `app.package_info().version.to_string()`,
  so Settings can show what's currently running.

`settings.rs` — one new field on `Settings` (the `#[serde(default)]` on the
struct means old stored settings deserialize fine):

```rust
/// Check GitHub for new releases in the background. Updates are never
/// installed without an explicit click — this only controls the check.
pub auto_check_updates: bool,   // default: true
```

---

## 6. UI

**Tray** (`tray.rs`) — one new `MenuItem`, placed above the `Settings…`
separator, following the existing `refresh_relay` pattern with a
`refresh_update(app, &UpdateStatus)`:

| Status | Menu item |
| --- | --- |
| `Idle` / `UpToDate` / `Checking` / `Error` | hidden (`set_visible(false)`) |
| `Available { version }` | `Update to v0.3.0…` → opens Settings |
| `Downloading { percent }` | `Downloading update… 42%` (disabled) |
| `Ready` | `Restart to finish update` → `install_update` |

When an update is available, append it to the tray tooltip too
(`Amallo — Relay: connected · Update available`) — that's the only
always-visible surface a tray app has.

**Settings window** — a new `<section class="card">` after "Behavior":

```
Updates
  Current version   0.2.0                       [ Check now ]
  <status line, reusing the existing .status classes>
  <release notes, only when Available>
  [ Install & Restart ]        <progress bar while downloading>
  ☐ Check for updates automatically
```

`main.ts` grows an `UpdateStatus` type and a `renderUpdateStatus()` mirroring
the existing `renderRelayStatus()`, plus a `listen("update-status", …)` in
`init()`. The `auto_check_updates` checkbox joins the existing
`persistSettings` loop over `[proxyPort, bindLan, relayUrl, autoConnectRelay]`.

**One extra confirmation**, because this is the piece the user can't undo: if
the relay is `Online` (a device is actually attached) when they press
"Install & Restart", confirm — *"A device is connected right now. Restarting
will interrupt it. Update anyway?"* — reusing the same `confirm()` style as
the existing regenerate-token / regenerate-pairing buttons. If the relay is
merely `Waiting` or `Disabled`, install without asking.

---

## 7. Testing

The updater is awkward to test because it needs two real signed builds and a
reachable endpoint. Concretely:

1. Build and install `0.2.0` normally (`npm run tauri build`, then run the
   installer — testing against `tauri dev` is meaningless; the updater is a
   no-op in dev).
2. Bump to `0.2.1`, build again with the signing env vars set.
3. Hand-write a `latest.json` pointing at the local `0.2.1` bundle, serve the
   directory over `http://localhost:8000`, and run the *installed* `0.2.0`
   against a dev config override:
   `npm run tauri build -- --config src-tauri/tauri.conf.updater-test.json`
   with `endpoints` pointed at localhost and
   `"dangerousInsecureTransportProtocol": true`. Do not let that override file
   near the release path.
4. Verify per platform: Windows (NSIS passive install, process exits and
   relaunches, `tauri-plugin-single-instance` doesn't misfire against the
   still-dying old process, autostart registration survives), macOS (bundle
   swap in `/Applications`, and the failure mode when the app lives somewhere
   unwritable).
5. Verify the relay reconnects after the restart and that `web` recovers the
   pairing without re-scanning.

Then a real end-to-end pass: cut an actual `0.2.1` release through the
workflow and confirm the published `latest.json` has **all three** platform
entries (this is the `max-parallel: 1` fix paying off — check it, don't assume
it).

---

## 8. Rollout order

1. Generate + back up keys, add secrets. *(blocks everything)*
2. `tauri.conf.json` + `Cargo.toml` + capabilities.
3. `update.rs`, state, commands, settings.
4. Tray + Settings UI.
5. Workflow changes (`max-parallel`, signing env, `createUpdaterArtifacts`).
6. Local two-build test, then a real release.
7. Only after a real release proves `latest.json` is correct: add the download
   link to `web`.

Step 7 is the point of no return — once people have installed Amallo, the
update channel has to keep working, and the pubkey in their binary is fixed
forever.

## Out of scope

- Staged / percentage rollouts and a remote kill switch. Would need the relay
  to serve the update manifest (dynamic-server mode) instead of a static
  `latest.json`. Revisit if a bad release ever needs to be pulled mid-flight.
- Apple code signing / notarization. Orthogonal to updating, but the thing
  most likely to be the *next* distribution complaint.
- Delta updates. Tauri doesn't do them; the full bundle is a few MB.
