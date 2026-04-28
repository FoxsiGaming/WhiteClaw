import { chromium } from "playwright";
import { ScanConfig, error, done, status } from "./models/finding";
import { spaFetch } from "./checks/spa_fetch";
import { analyzeForms } from "./checks/forms";
import { analyzeDOM } from "./checks/dom";
import { interceptEndpoints } from "./checks/js_endpoints";

async function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
  });
}

async function main(): Promise<void> {
  const raw = await readStdin();

  let cfg: ScanConfig;
  try {
    cfg = JSON.parse(raw.trim());
  } catch (e) {
    error("Failed to parse scan config: " + String(e));
    done();
    return;
  }
  if (!cfg.timeout) {
    cfg.timeout = 30_000;
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  });

  try {
    status("Crawler: launching headless browser...");

    // --- Phase 1: initial render + cookie checks ---
    const fetchPage = await context.newPage();
    await spaFetch(fetchPage, cfg);
    await fetchPage.close();

    // --- Phase 2: DOM analysis (forms, hidden inputs, comments) ---
    const domPage = await context.newPage();
    await domPage.goto(cfg.url, { waitUntil: "networkidle", timeout: cfg.timeout }).catch(() => {});
    await Promise.all([
      analyzeForms(domPage, cfg),
      analyzeDOM(domPage, cfg),
    ]);
    await domPage.close();

    // --- Phase 3: network interception for dynamic API discovery ---
    const interceptPage = await context.newPage();
    await interceptEndpoints(interceptPage, cfg);
    await interceptPage.close();
  } catch (e) {
    error("Crawler unhandled error: " + String(e));
  } finally {
    await browser.close();
    done();
  }
}

main().catch((e) => {
  error("Crawler fatal: " + String(e));
  done();
});
