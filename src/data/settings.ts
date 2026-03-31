import { DEFAULT_SETTINGS, type ExtensionSettings } from "../shared/types";

const KEY = "ca_settings_v1";

export async function loadSettings(): Promise<ExtensionSettings> {
  const raw = await chrome.storage.local.get(KEY);
  const v = raw[KEY] as Partial<ExtensionSettings> | undefined;
  if (!v || typeof v !== "object") {
    return { ...DEFAULT_SETTINGS };
  }
  return {
    ...DEFAULT_SETTINGS,
    ...v,
  };
}

export async function saveSettings(
  partial: Partial<ExtensionSettings>,
): Promise<ExtensionSettings> {
  const cur = await loadSettings();
  const next = { ...cur, ...partial };
  await chrome.storage.local.set({ [KEY]: next });
  return next;
}
