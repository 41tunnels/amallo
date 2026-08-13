import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface Settings {
  proxy_port: number;
  bind_lan: boolean;
  relay_url: string;
  auto_connect_relay: boolean;
  openai_endpoint_enabled: boolean;
}

interface OpenAiEndpoint {
  enabled: boolean;
  base_url: string;
  api_key: string;
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
const lanUrlRow = $<HTMLDivElement>("lan-url-row");
const lanUrl = $<HTMLInputElement>("lan-url");
const bearerToken = $<HTMLInputElement>("bearer-token");
const autostart = $<HTMLInputElement>("autostart");

const pairingQr = $<HTMLDivElement>("pairing-qr");
const pairingCode = $<HTMLInputElement>("pairing-code");
const relayUrl = $<HTMLInputElement>("relay-url");
const autoConnectRelay = $<HTMLInputElement>("auto-connect-relay");
const relayStatusEl = $<HTMLElement>("relay-status");
const toggleRelayBtn = $<HTMLButtonElement>("toggle-relay");

const openaiEnabled = $<HTMLInputElement>("openai-enabled");
const openaiDetails = $<HTMLDivElement>("openai-details");
const openaiBaseUrl = $<HTMLInputElement>("openai-base-url");
const openaiKey = $<HTMLInputElement>("openai-key");

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

// The base URL embeds the API key (some clients accept only a base URL),
// so it has to be re-read after a key rotation as well as on load.
async function refreshOpenAI() {
  const endpoint = await invoke<OpenAiEndpoint>("get_openai_endpoint");
  openaiBaseUrl.value = endpoint.base_url;
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

  await refreshLanUrl();
  await refreshOpenAI();
  bearerToken.value = await invoke<string>("get_bearer_token");
  autostart.checked = await invoke<boolean>("get_autostart").catch(() => false);
  renderRelayStatus(await invoke<RelayStatus>("get_relay_status"));
  await refreshPairing();

  await listen<RelayStatus>("relay-status", (event) =>
    renderRelayStatus(event.payload),
  );
}

$<HTMLButtonElement>("copy-lan-url").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: lanUrl.value });
  flash(e.currentTarget as HTMLButtonElement, "Copied ✓");
});

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
    openai_endpoint_enabled: openaiEnabled.checked,
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

for (const el of [proxyPort, bindLan, relayUrl, autoConnectRelay, openaiEnabled]) {
  el.addEventListener("change", () => persistSettings(el));
}

$<HTMLButtonElement>("copy-openai-url").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: openaiBaseUrl.value });
  flash(e.currentTarget as HTMLButtonElement, "Copied ✓");
});

$<HTMLButtonElement>("copy-openai-key").addEventListener("click", async (e) => {
  await invoke("copy_to_clipboard", { text: openaiKey.value });
  flash(e.currentTarget as HTMLButtonElement, "Copied ✓");
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
