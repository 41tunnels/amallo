import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";

interface Settings {
  proxy_port: number;
  bind_lan: boolean;
  relay_url: string;
  auto_connect_relay: boolean;
  openai_endpoint_enabled: boolean;
  auto_update: boolean;
}

interface OpenAiEndpoint {
  enabled: boolean;
  base_url: string;
  api_key: string;
  path_base_url: string;
}

// Mirrors `UpdateStatus` in state.rs. "deferred" means an update is ready
// to install on its own but a device is attached right now.
type UpdateStatus =
  | { state: "idle" }
  | { state: "available"; version: string }
  | { state: "deferred"; version: string }
  | { state: "downloading"; version: string }
  | { state: "failed"; message: string };

type RelayStatus =
  | { state: "disabled" }
  | { state: "connecting" }
  | { state: "waiting" }
  | { state: "online" }
  | { state: "offline" }
  | { state: "error"; message: string };

const $ = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;

const proxyPort = $<HTMLInputElement>("proxy-port");
const bindLan = $<HTMLInputElement>("bind-lan");
const lanUrlRow = $<HTMLDivElement>("lan-url-row");
const lanUrl = $<HTMLInputElement>("lan-url");
const bearerToken = $<HTMLInputElement>("bearer-token");
const autostart = $<HTMLInputElement>("autostart");

const pairingQr = $<HTMLDivElement>("pairing-qr");
const pairingCode = $<HTMLInputElement>("pairing-code");
const relayUrl = $<HTMLInputElement>("relay-url");
const autoConnectRelay = $<HTMLInputElement>("auto-connect-relay");
const relayStatusEl = $<HTMLElement>("relay-status");
const relayStatusText = $<HTMLElement>("relay-status-text");
const toggleRelayBtn = $<HTMLButtonElement>("toggle-relay");

const updateBanner = $<HTMLDivElement>("update-banner");
const updateText = $<HTMLElement>("update-text");
const updateHint = $<HTMLElement>("update-hint");
const installUpdateBtn = $<HTMLButtonElement>("install-update");
const autoUpdate = $<HTMLInputElement>("auto-update");
const appVersion = $<HTMLElement>("app-version");

const openaiEnabled = $<HTMLInputElement>("openai-enabled");
const openaiDetails = $<HTMLDivElement>("openai-details");
const openaiBaseUrl = $<HTMLInputElement>("openai-base-url");
const openaiPathBaseUrl = $<HTMLInputElement>("openai-path-base-url");
const openaiKey = $<HTMLInputElement>("openai-key");

let currentRelayStatus: RelayStatus = { state: "disabled" };

function renderRelayStatus(status: RelayStatus) {
  currentRelayStatus = status;
  relayStatusEl.className = `t-status ${status.state}`;
  switch (status.state) {
    case "disabled":
      relayStatusText.textContent = "Relay disabled";
      toggleRelayBtn.textContent = "Connect Relay";
      break;
    case "connecting":
      relayStatusText.textContent = "Connecting…";
      toggleRelayBtn.textContent = "Disconnect Relay";
      break;
    case "waiting":
      relayStatusText.textContent = "Waiting for a device…";
      toggleRelayBtn.textContent = "Disconnect Relay";
      break;
    case "online":
      relayStatusText.textContent = "Relay connected";
      toggleRelayBtn.textContent = "Disconnect Relay";
      break;
    case "offline":
      relayStatusText.textContent = "Offline, retrying…";
      toggleRelayBtn.textContent = "Disconnect Relay";
      break;
    case "error":
      relayStatusText.textContent = `Relay error: ${status.message}`;
      toggleRelayBtn.textContent = "Connect Relay";
      break;
  }
}

function renderUpdateStatus(status: UpdateStatus) {
  updateBanner.hidden = status.state === "idle";
  updateBanner.dataset.state = status.state;
  // Only "downloading" is uninterruptible; every other visible state has
  // something for the button to do.
  installUpdateBtn.disabled = status.state === "downloading";
  updateHint.hidden = true;

  switch (status.state) {
    case "idle":
      break;
    case "available":
      updateText.textContent = `Amallo ${status.version} is available`;
      installUpdateBtn.textContent = "Install and restart";
      break;
    case "deferred":
      updateText.textContent = `Amallo ${status.version} is available`;
      updateHint.textContent =
        "installs on its own once no device is connected";
      updateHint.hidden = false;
      installUpdateBtn.textContent = "Install now";
      break;
    case "downloading":
      updateText.textContent = `Downloading ${status.version}…`;
      installUpdateBtn.textContent = "Downloading…";
      break;
    case "failed":
      updateText.textContent = "Update failed";
      updateHint.textContent = status.message;
      updateHint.hidden = false;
      installUpdateBtn.textContent = "Try again";
      break;
  }
}

async function refreshPairing() {
  pairingCode.value = await invoke<string>("get_pairing_code");
  pairingQr.innerHTML = await invoke<string>("get_pairing_qr");
}

const COPIED_ICON =
  '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M3 8.4l3.2 3.2L13 4.8"/></svg>';

// Copy buttons are icon-only, so "flash a confirmation" means swapping the
// icon rather than the old text-button's label.
function flashCopied(button: HTMLButtonElement) {
  if (button.dataset.busy) return;
  const originalHtml = button.innerHTML;
  const originalLabel = button.getAttribute("aria-label");
  button.dataset.busy = "1";
  button.innerHTML = COPIED_ICON;
  button.setAttribute("aria-label", "Copied");
  setTimeout(() => {
    button.innerHTML = originalHtml;
    if (originalLabel) button.setAttribute("aria-label", originalLabel);
    delete button.dataset.busy;
  }, 1200);
}

// Every credential in this window renders masked, and each one carries its
// own reveal. The settings window is what a user screen-shares when asking
// for help, and all four of these values (the pairing URL and the fallback
// OpenAI path URL included — they embed the PSK and the API key
// respectively) are live credentials, not identifiers. The plain OpenAI
// base URL is deliberately not among them: it carries no secret.
for (const button of document.querySelectorAll<HTMLButtonElement>("[data-reveal]")) {
  const input = $<HTMLInputElement>(button.dataset.reveal!);
  button.addEventListener("click", () => {
    const revealed = button.getAttribute("aria-pressed") === "true";
    button.setAttribute("aria-pressed", String(!revealed));
    input.classList.toggle("is-masked", revealed);
    const label = button.getAttribute("aria-label")!;
    button.setAttribute(
      "aria-label",
      revealed ? label.replace(/^Hide/, "Show") : label.replace(/^Show/, "Hide"),
    );
    button.title = revealed ? "Show" : "Hide";
  });
}

// Switch tracks read their on/off visual from data-checked (the same
// contract the design system's Switch component uses) rather than the
// underlying, visually-hidden <input>, so it has to be kept in sync
// whenever a switch's `checked` is set from JS instead of user input.
function syncSwitch(input: HTMLInputElement) {
  input.closest(".t-switch")?.setAttribute("data-checked", String(input.checked));
}

// The base URL is keyless and survives a rotation untouched; the
// fallback path URL embeds the key and does not, so both are re-read
// after a rotation as well as on load.
async function refreshOpenAI() {
  const endpoint = await invoke<OpenAiEndpoint>("get_openai_endpoint");
  openaiBaseUrl.value = endpoint.base_url;
  openaiPathBaseUrl.value = endpoint.path_base_url;
  openaiKey.value = endpoint.api_key;
  openaiDetails.hidden = !openaiEnabled.checked;
}

async function refreshLanUrl() {
  lanUrlRow.hidden = !bindLan.checked;
  if (bindLan.checked) {
    lanUrl.value = await invoke<string>("get_lan_url");
  }
}

async function init() {
  const settings = await invoke<Settings>("get_settings");
  proxyPort.value = String(settings.proxy_port);
  bindLan.checked = settings.bind_lan;
  relayUrl.value = settings.relay_url;
  autoConnectRelay.checked = settings.auto_connect_relay;
  openaiEnabled.checked = settings.openai_endpoint_enabled;
  autoUpdate.checked = settings.auto_update;
  for (const el of [bindLan, autoConnectRelay, openaiEnabled, autoUpdate])
    syncSwitch(el);

  await refreshLanUrl();
  await refreshOpenAI();
  bearerToken.value = await invoke<string>("get_bearer_token");
  autostart.checked = await invoke<boolean>("get_autostart").catch(() => false);
  syncSwitch(autostart);
  renderRelayStatus(await invoke<RelayStatus>("get_relay_status"));
  renderUpdateStatus(await invoke<UpdateStatus>("get_update_status"));
  appVersion.textContent = await getVersion();
  await refreshPairing();

  await listen<RelayStatus>("relay-status", (event) =>
    renderRelayStatus(event.payload),
  );
  await listen<UpdateStatus>("update-status", (event) =>
    renderUpdateStatus(event.payload),
  );
}

$<HTMLButtonElement>("copy-lan-url").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: lanUrl.value });
  flashCopied(e.currentTarget as HTMLButtonElement);
});

$<HTMLButtonElement>("copy-bearer").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: bearerToken.value });
  flashCopied(e.currentTarget as HTMLButtonElement);
});

$<HTMLButtonElement>("regen-bearer").addEventListener("click", async () => {
  if (
    !confirm(
      "Regenerate the bearer token? Clients using the old token lose access immediately.",
    )
  )
    return;
  bearerToken.value = await invoke<string>("regenerate_bearer_token");
});

// Settings persist automatically on change — no Save button to forget.
// A switch's <input> is visually hidden, so the outline goes on its
// .t-switch wrapper instead; plain inputs (relay URL, port) take it directly.
function markSaved(el: HTMLElement) {
  const target = el.closest(".t-switch") ?? el;
  target.classList.add("just-saved");
  setTimeout(() => target.classList.remove("just-saved"), 900);
}

async function persistSettings(changed: HTMLElement) {
  const newSettings: Settings = {
    proxy_port: Math.min(65535, Math.max(1024, Number(proxyPort.value) || 11435)),
    bind_lan: bindLan.checked,
    relay_url: relayUrl.value.trim(),
    auto_connect_relay: autoConnectRelay.checked,
    openai_endpoint_enabled: openaiEnabled.checked,
    auto_update: autoUpdate.checked,
  };
  proxyPort.value = String(newSettings.proxy_port);
  relayUrl.value = newSettings.relay_url;
  await invoke("save_settings", { newSettings });
  markSaved(changed);
  // The pairing code/QR embed the relay URL — regenerate the displayed
  // one so it doesn't silently point a scanned code at the old relay.
  if (changed === relayUrl) await refreshPairing();
  if (changed === bindLan || changed === proxyPort) await refreshLanUrl();
  // The OpenAI base URL is derived from the relay URL, so it goes stale
  // for the same reason the pairing code does.
  if (changed === relayUrl || changed === openaiEnabled) await refreshOpenAI();
}

for (const el of [
  proxyPort,
  bindLan,
  relayUrl,
  autoConnectRelay,
  openaiEnabled,
  autoUpdate,
]) {
  el.addEventListener("change", () => {
    syncSwitch(el);
    persistSettings(el);
  });
}

$<HTMLButtonElement>("copy-openai-url").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: openaiBaseUrl.value });
  flashCopied(e.currentTarget as HTMLButtonElement);
});

$<HTMLButtonElement>("copy-openai-path-url").addEventListener(
  "click",
  async (e) => {
    await invoke("copy_to_clipboard", { text: openaiPathBaseUrl.value });
    flashCopied(e.currentTarget as HTMLButtonElement);
  },
);

$<HTMLButtonElement>("copy-openai-key").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: openaiKey.value });
  flashCopied(e.currentTarget as HTMLButtonElement);
});

$<HTMLButtonElement>("regen-openai-key").addEventListener("click", async () => {
  if (
    !confirm(
      "Regenerate the API key? Every app configured with the old key stops working immediately.",
    )
  )
    return;
  await invoke<string>("regenerate_openai_key");
  await refreshOpenAI();
});

installUpdateBtn.addEventListener("click", async () => {
  // The automatic path refuses to install mid-session; this button is how
  // a user overrides that, so it has to say what it will cost them first.
  if (
    currentRelayStatus.state === "online" &&
    !confirm(
      "A device is connected right now. Installing restarts Amallo and drops that connection. Install anyway?",
    )
  )
    return;

  // On success this never resolves — installing restarts the app. Only the
  // failure path comes back, and update-status has already been emitted
  // with the reason by then.
  await invoke("install_update").catch((e) => {
    console.error("install_update failed", e);
  });
});

autostart.addEventListener("change", async () => {
  syncSwitch(autostart);
  await invoke("set_autostart", { enabled: autostart.checked }).catch(() => {});
  markSaved(autostart);
});

$<HTMLButtonElement>("copy-pairing-code").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: pairingCode.value });
  flashCopied(e.currentTarget as HTMLButtonElement);
});

$<HTMLButtonElement>("regen-pairing").addEventListener("click", async () => {
  if (
    !confirm(
      "Regenerate the pairing code? Every device currently paired (including web) loses access immediately.",
    )
  )
    return;
  await invoke<string>("regenerate_pairing");
  await refreshPairing();
});

toggleRelayBtn.addEventListener("click", async () => {
  if (
    currentRelayStatus.state === "online" ||
    currentRelayStatus.state === "waiting" ||
    currentRelayStatus.state === "connecting"
  ) {
    await invoke("disconnect_relay");
  } else {
    await invoke("connect_relay");
  }
});

init();
