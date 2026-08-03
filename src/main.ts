import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface Settings {
  static_domain: string | null;
  proxy_port: number;
  bind_lan: boolean;
  auto_start_tunnel: boolean;
  relay_url: string;
  auto_connect_relay: boolean;
}

type TunnelStatus =
  | { state: "stopped" }
  | { state: "connecting" }
  | { state: "running"; url: string }
  | { state: "error"; message: string };

type RelayStatus =
  | { state: "disabled" }
  | { state: "connecting" }
  | { state: "waiting" }
  | { state: "online" }
  | { state: "offline" }
  | { state: "error"; message: string };

const $ = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;

const ngrokToken = $<HTMLInputElement>("ngrok-token");
const ngrokTokenState = $<HTMLSpanElement>("ngrok-token-state");
const staticDomain = $<HTMLInputElement>("static-domain");
const proxyPort = $<HTMLInputElement>("proxy-port");
const bindLan = $<HTMLInputElement>("bind-lan");
const bearerToken = $<HTMLInputElement>("bearer-token");
const autostart = $<HTMLInputElement>("autostart");
const autoStartTunnel = $<HTMLInputElement>("auto-start-tunnel");
const statusEl = $<HTMLElement>("status");
const toggleBtn = $<HTMLButtonElement>("toggle-tunnel");

const pairingQr = $<HTMLDivElement>("pairing-qr");
const pairingCode = $<HTMLInputElement>("pairing-code");
const relayUrl = $<HTMLInputElement>("relay-url");
const autoConnectRelay = $<HTMLInputElement>("auto-connect-relay");
const relayStatusEl = $<HTMLElement>("relay-status");
const toggleRelayBtn = $<HTMLButtonElement>("toggle-relay");

let currentStatus: TunnelStatus = { state: "stopped" };
let currentRelayStatus: RelayStatus = { state: "disabled" };

function renderStatus(status: TunnelStatus) {
  currentStatus = status;
  statusEl.className = `status ${status.state}`;
  switch (status.state) {
    case "stopped":
      statusEl.textContent = "Tunnel: stopped";
      toggleBtn.textContent = "Start Tunnel";
      break;
    case "connecting":
      statusEl.textContent = "Tunnel: connecting…";
      toggleBtn.textContent = "Stop Tunnel";
      break;
    case "running":
      statusEl.textContent = `Online: ${status.url} (click to copy)`;
      toggleBtn.textContent = "Stop Tunnel";
      break;
    case "error":
      statusEl.textContent = `Error: ${status.message}`;
      toggleBtn.textContent = "Start Tunnel";
      break;
  }
}

function renderRelayStatus(status: RelayStatus) {
  currentRelayStatus = status;
  relayStatusEl.className = `status ${status.state}`;
  switch (status.state) {
    case "disabled":
      relayStatusEl.textContent = "Relay: disabled";
      toggleRelayBtn.textContent = "Connect Relay";
      break;
    case "connecting":
      relayStatusEl.textContent = "Relay: connecting…";
      toggleRelayBtn.textContent = "Disconnect Relay";
      break;
    case "waiting":
      relayStatusEl.textContent = "Relay: waiting for a device…";
      toggleRelayBtn.textContent = "Disconnect Relay";
      break;
    case "online":
      relayStatusEl.textContent = "Relay: connected";
      toggleRelayBtn.textContent = "Disconnect Relay";
      break;
    case "offline":
      relayStatusEl.textContent = "Relay: offline, retrying…";
      toggleRelayBtn.textContent = "Disconnect Relay";
      break;
    case "error":
      relayStatusEl.textContent = `Relay error: ${status.message}`;
      toggleRelayBtn.textContent = "Connect Relay";
      break;
  }
}

async function refreshPairing() {
  pairingCode.value = await invoke<string>("get_pairing_code");
  pairingQr.innerHTML = await invoke<string>("get_pairing_qr");
}

async function refreshNgrokTokenState() {
  const hasToken = await invoke<boolean>("has_ngrok_token");
  ngrokTokenState.textContent = hasToken ? "— saved ✓" : "— not set";
  ngrokToken.placeholder = hasToken
    ? "•••••••• (saved — paste to replace)"
    : "paste your ngrok authtoken";
}

function flash(button: HTMLButtonElement, label: string) {
  const original = button.textContent;
  button.textContent = label;
  setTimeout(() => (button.textContent = original), 1200);
}

async function init() {
  const settings = await invoke<Settings>("get_settings");
  staticDomain.value = settings.static_domain ?? "";
  proxyPort.value = String(settings.proxy_port);
  bindLan.checked = settings.bind_lan;
  autoStartTunnel.checked = settings.auto_start_tunnel;
  relayUrl.value = settings.relay_url;
  autoConnectRelay.checked = settings.auto_connect_relay;

  bearerToken.value = await invoke<string>("get_bearer_token");
  autostart.checked = await invoke<boolean>("get_autostart").catch(() => false);
  renderStatus(await invoke<TunnelStatus>("get_status"));
  renderRelayStatus(await invoke<RelayStatus>("get_relay_status"));
  await refreshNgrokTokenState();
  await refreshPairing();

  await listen<TunnelStatus>("tunnel-status", (event) =>
    renderStatus(event.payload),
  );
  await listen<RelayStatus>("relay-status", (event) =>
    renderRelayStatus(event.payload),
  );
}

$<HTMLButtonElement>("copy-bearer").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: bearerToken.value });
  flash(e.currentTarget as HTMLButtonElement, "Copied ✓");
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
function markSaved(el: HTMLElement) {
  el.classList.add("just-saved");
  setTimeout(() => el.classList.remove("just-saved"), 900);
}

async function persistSettings(changed: HTMLElement) {
  const newSettings: Settings = {
    static_domain: staticDomain.value.trim() || null,
    proxy_port: Math.min(65535, Math.max(1024, Number(proxyPort.value) || 11435)),
    bind_lan: bindLan.checked,
    auto_start_tunnel: autoStartTunnel.checked,
    relay_url: relayUrl.value.trim(),
    auto_connect_relay: autoConnectRelay.checked,
  };
  proxyPort.value = String(newSettings.proxy_port);
  relayUrl.value = newSettings.relay_url;
  await invoke("save_settings", { newSettings });
  markSaved(changed);
  // The pairing code/QR embed the relay URL — regenerate the displayed
  // one so it doesn't silently point a scanned code at the old relay.
  if (changed === relayUrl) await refreshPairing();
}

for (const el of [staticDomain, proxyPort, bindLan, autoStartTunnel, relayUrl, autoConnectRelay]) {
  el.addEventListener("change", () => persistSettings(el));
}

// The authtoken is write-only: save it on change only when something was typed,
// then clear the field and reflect the saved state.
ngrokToken.addEventListener("change", async () => {
  if (!ngrokToken.value) return;
  await invoke("set_ngrok_token", { token: ngrokToken.value });
  ngrokToken.value = "";
  await refreshNgrokTokenState();
  markSaved(ngrokTokenState);
});

autostart.addEventListener("change", async () => {
  await invoke("set_autostart", { enabled: autostart.checked }).catch(() => {});
  markSaved(autostart);
});

toggleBtn.addEventListener("click", async () => {
  if (
    currentStatus.state === "running" ||
    currentStatus.state === "connecting"
  ) {
    await invoke("stop_tunnel");
  } else {
    // Fire and forget: status updates arrive via the tunnel-status event.
    invoke("start_tunnel");
  }
});

statusEl.addEventListener("click", async () => {
  if (currentStatus.state === "running") {
    await invoke("copy_to_clipboard", { text: currentStatus.url });
  }
});

$<HTMLButtonElement>("copy-pairing-code").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: pairingCode.value });
  flash(e.currentTarget as HTMLButtonElement, "Copied ✓");
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
