import { Page } from "playwright";
import { ScanConfig, emit, status } from "../models/finding";

/**
 * Navigates to the target URL with a full headless browser, waits for network
 * idle, then checks rendered cookies for missing security flags.
 * This catches issues on SPAs where the initial HTML is nearly empty.
 */
export async function spaFetch(page: Page, cfg: ScanConfig): Promise<void> {
  status("Crawler: fetching page (waiting for network idle)...");
  try {
    await page.goto(cfg.url, {
      waitUntil: "networkidle",
      timeout: cfg.timeout,
    });
  } catch (e) {
    emit({ type: "error", message: `spaFetch: navigation failed — ${String(e)}` });
    return;
  }

  const cookies = await page.context().cookies();
  for (const c of cookies) {
    if (!c.httpOnly) {
      emit({
        type: "finding",
        severity: "MEDIUM",
        category: "vulnerabilities",
        title: `Cookie missing HttpOnly (JS-accessible): ${c.name}`,
        detail: `Cookie "${c.name}" has no HttpOnly flag — readable by JavaScript. Domain: ${c.domain}`,
        fix: "Set HttpOnly on all session and authentication cookies.",
      });
    }
    if (!c.secure) {
      emit({
        type: "finding",
        severity: "MEDIUM",
        category: "vulnerabilities",
        title: `Cookie missing Secure flag: ${c.name}`,
        detail: `Cookie "${c.name}" can be transmitted over plain HTTP. Domain: ${c.domain}`,
        fix: "Add the Secure flag to all cookies.",
      });
    }
    if (!c.sameSite || c.sameSite === "None") {
      emit({
        type: "finding",
        severity: "LOW",
        category: "vulnerabilities",
        title: `Cookie missing SameSite: ${c.name}`,
        detail: `Cookie "${c.name}" has no SameSite restriction. Domain: ${c.domain}`,
        fix: "Set SameSite=Strict or SameSite=Lax on all cookies.",
      });
    }
  }
}
