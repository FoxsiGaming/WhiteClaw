import { Page, Request } from "playwright";
import { ScanConfig, emit, status } from "../models/finding";

/**
 * Intercepts every network request made by the page after full render.
 * Same-origin API calls (XHR/fetch) are reported as discovered endpoints.
 * This catches dynamically-constructed URLs that static regex cannot find.
 */
export async function interceptEndpoints(page: Page, cfg: ScanConfig): Promise<void> {
  status("Crawler: intercepting network requests for API discovery...");

  const discovered = new Set<string>();
  let cfgOrigin: string;
  try {
    cfgOrigin = new URL(cfg.base_url).origin;
  } catch {
    return;
  }

  page.on("request", (req: Request) => {
    const resourceType = req.resourceType();
    // Only care about XHR / fetch calls, not page assets
    if (resourceType !== "xhr" && resourceType !== "fetch") {
      return;
    }
    const url = req.url();
    try {
      const parsed = new URL(url);
      if (parsed.origin !== cfgOrigin) {
        return;
      }
      const key = `${req.method()}:${parsed.pathname}`;
      if (!discovered.has(key)) {
        discovered.add(key);
        emit({
          type: "finding",
          severity: "INFO",
          category: "apis",
          title: `Dynamic API call intercepted: ${req.method()} ${parsed.pathname}`,
          detail: `Full URL: ${url}`,
          fix: "Ensure this endpoint enforces authentication and is included in your API security review.",
        });
      }
    } catch {
      // malformed URL — ignore
    }
  });

  // Re-navigate (or interact with the page) to trigger lazy-loaded XHR calls
  try {
    await page.goto(cfg.url, {
      waitUntil: "networkidle",
      timeout: cfg.timeout,
    });
    // Give the SPA a moment to fire post-render requests (e.g., lazy route prefetch)
    await page.waitForTimeout(2500);
  } catch (e) {
    emit({ type: "error", message: `interceptEndpoints: ${String(e)}` });
  }
}
