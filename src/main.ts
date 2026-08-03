import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface Settings {
  proxy_port: number;
  bind_lan: boolean;
  relay_url: string;
  auto_connect_relay: boolean;
}

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
const bearerToken = $<HTMLInputElement>("bearer-token");
const autostart = $<HTMLInputElement>("autostart");

const pairingQr = $<HTMLDivElement>("pairing-qr");
const pairingCode = $<HTMLInputElement>("pairing-code");
const relayUrl = $<HTMLInputElement>("relay-url");
const autoConnectRelay = $<HTMLInputElement>("auto-connect-relay");
const relayStatusEl = $<HTMLElement>("relay-status");
const toggleRelayBtn = $<HTMLButtonElement>("toggle-relay");

let currentRelayStatus: RelayStatus = { state: "disabled" };

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

function flash(button: HTMLButtonElement, label: string) {
  const original = button.textContent;
  button.textContent = label;
  setTimeout(() => (button.textContent = original), 1200);
}

async function init() {
  const settings = await invoke<Settings>("get_settings");
  proxyPort.value = String(settings.proxy_port);
  bindLan.checked = settings.bind_lan;
  relayUrl.value = settings.relay_url;
  autoConnectRelay.checked = settings.auto_connect_relay;

  bearerToken.value = await invoke<string>("get_bearer_token");
  autostart.checked = await invoke<boolean>("get_autostart").catch(() => false);
  renderRelayStatus(await invoke<RelayStatus>("get_relay_status"));
  await refreshPairing();

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
    proxy_port: Math.min(65535, Math.max(1024, Number(proxyPort.value) || 11435)),
    bind_lan: bindLan.checked,
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

for (const el of [proxyPort, bindLan, relayUrl, autoConnectRelay]) {
  el.addEventListener("change", () => persistSettings(el));
}

autostart.addEventListener("change", async () => {
  await invoke("set_autostart", { enabled: autostart.checked }).catch(() => {});
  markSaved(autostart);
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
