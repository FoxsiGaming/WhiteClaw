"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const playwright_1 = require("playwright");
const finding_1 = require("./models/finding");
const spa_fetch_1 = require("./checks/spa_fetch");
const forms_1 = require("./checks/forms");
const dom_1 = require("./checks/dom");
const js_endpoints_1 = require("./checks/js_endpoints");
async function readStdin() {
    return new Promise((resolve) => {
        let data = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (chunk) => (data += chunk));
        process.stdin.on("end", () => resolve(data));
    });
}
async function main() {
    const raw = await readStdin();
    let cfg;
    try {
        cfg = JSON.parse(raw.trim());
    }
    catch (e) {
        (0, finding_1.error)("Failed to parse scan config: " + String(e));
        (0, finding_1.done)();
        return;
    }
    if (!cfg.timeout) {
        cfg.timeout = 30000;
    }
    const browser = await playwright_1.chromium.launch({ headless: true });
    const context = await browser.newContext({
        ignoreHTTPSErrors: true,
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    });
    try {
        (0, finding_1.status)("Crawler: launching headless browser...");
        // --- Phase 1: initial render + cookie checks ---
        const fetchPage = await context.newPage();
        await (0, spa_fetch_1.spaFetch)(fetchPage, cfg);
        await fetchPage.close();
        // --- Phase 2: DOM analysis (forms, hidden inputs, comments) ---
        const domPage = await context.newPage();
        await domPage.goto(cfg.url, { waitUntil: "networkidle", timeout: cfg.timeout }).catch(() => { });
        await Promise.all([
            (0, forms_1.analyzeForms)(domPage, cfg),
            (0, dom_1.analyzeDOM)(domPage, cfg),
        ]);
        await domPage.close();
        // --- Phase 3: network interception for dynamic API discovery ---
        const interceptPage = await context.newPage();
        await (0, js_endpoints_1.interceptEndpoints)(interceptPage, cfg);
        await interceptPage.close();
    }
    catch (e) {
        (0, finding_1.error)("Crawler unhandled error: " + String(e));
    }
    finally {
        await browser.close();
        (0, finding_1.done)();
    }
}
main().catch((e) => {
    (0, finding_1.error)("Crawler fatal: " + String(e));
    (0, finding_1.done)();
});
