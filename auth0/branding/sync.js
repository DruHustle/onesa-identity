import { isDeepStrictEqual } from "node:util";
import theme from "./theme.json" with { type: "json" };
import copy from "./text.json" with { type: "json" };

const api = "https://onesa.eu.auth0.com/api/v2";
const defaultTheme = "/branding/themes/default";

function managedTheme(current) {
  // Each PATCH group may contain tenant-specific settings such as an existing font.
  return Object.fromEntries(Object.entries(theme).map(([group, fields]) => [
    group, { ...current?.[group], ...fields },
  ]));
}

function matchesTheme(current) {
  return !!current && Object.entries(theme).every(([group, fields]) =>
    Object.entries(fields).every(([key, value]) => {
      const actual = current[group]?.[key];
      if (group === "colors" || key === "background_color") {
        return typeof actual === "string" && actual.toLowerCase() === value.toLowerCase();
      }
      return isDeepStrictEqual(actual, value);
    }),
  );
}

export async function syncBranding(request, apply = false) {
  const pending = [];
  const current = await request(defaultTheme, "GET", undefined, true);
  if (!matchesTheme(current)) {
    pending.push("Universal Login theme");
    if (apply) {
      if (current) {
        if (!current.themeId) throw new Error("Auth0 returned a default theme without an ID.");
        await request("/branding/themes/" + encodeURIComponent(current.themeId), "PATCH", managedTheme(current));
      } else {
        await request("/branding/themes", "POST", theme);
      }
    }
  }
  // Prompt text PUT replaces all overrides for this language/prompt.
  // Preserve other screens and any labels that Onesa does not own.
  for (const [language, strings] of Object.entries(copy)) {
    for (const [screen, fields] of Object.entries(strings)) {
      const path = "/prompts/" + screen + "/custom-text/" + language;
      const prior = await request(path, "GET");
      const next = { ...prior, [screen]: { ...prior[screen], ...fields } };
      if (isDeepStrictEqual(prior, next)) continue;
      pending.push(language + " " + screen);
      if (apply) await request(path, "PUT", next);
    }
  }
  return pending;
}

if (import.meta.main) {
  const mode = process.argv[2];
  const token = process.env.AUTH0_MANAGEMENT_TOKEN;
  if (!["--check", "--apply"].includes(mode) || !token) {
    console.error("Set AUTH0_MANAGEMENT_TOKEN for the Onesa tenant and use --check or --apply.");
    process.exitCode = 2;
  } else {
    const request = async (path, method, body, allowMissing = false) => {
      const response = await fetch(api + path, {
        method, redirect: "error", signal: AbortSignal.timeout(15000),
        headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (allowMissing && response.status === 404) return null;
      if (!response.ok) throw new Error(method + " " + path + " returned HTTP " + response.status);
      if (method === "GET") return response.json();
      await response.body?.cancel();
    };
    try {
      if (mode === "--apply") await syncBranding(request, true);
      const pending = await syncBranding(request, false);
      console.log(pending.length ? "Pending: " + pending.join(", ") : "Verified Onesa Universal Login theme and text.");
      process.exitCode = pending.length ? 1 : 0;
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  }
}
