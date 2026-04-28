"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeForms = analyzeForms;
const finding_1 = require("../models/finding");
/**
 * Analyses rendered forms for missing CSRF tokens and insecure autocomplete
 * on password fields.  Runs after spaFetch so the DOM is fully rendered.
 */
async function analyzeForms(page, cfg) {
    (0, finding_1.status)("Crawler: analysing forms (CSRF, autocomplete)...");
    const forms = await page.evaluate(() => {
        const csrfKeys = ["csrf", "_token", "authenticity_token", "nonce", "xsrf"];
        return Array.from(document.querySelectorAll("form")).map((form) => {
            const inputs = Array.from(form.querySelectorAll("input")).map((inp) => ({
                name: inp.name || inp.id || "(unnamed)",
                type: inp.type || "text",
                autocomplete: inp.getAttribute("autocomplete"),
            }));
            const hasCsrf = inputs.some((i) => csrfKeys.some((k) => i.name.toLowerCase().includes(k)));
            return {
                action: form.action || window.location.href,
                method: (form.method || "GET").toUpperCase(),
                inputCount: inputs.length,
                hasCsrf,
                inputs,
            };
        });
    });
    for (let i = 0; i < forms.length; i++) {
        const form = forms[i];
        const hasPassword = form.inputs.some((inp) => inp.type === "password");
        if ((form.method === "POST" || hasPassword) && !form.hasCsrf) {
            (0, finding_1.emit)({
                type: "finding",
                severity: "HIGH",
                category: "vulnerabilities",
                title: `Form #${i + 1} missing CSRF token`,
                detail: `${form.method} form (action: ${form.action}) has no detectable CSRF token among ${form.inputCount} input(s).`,
                fix: "Add a synchroniser token or double-submit cookie CSRF defence to all state-changing forms.",
            });
        }
        for (const inp of form.inputs) {
            if (inp.type === "password" &&
                inp.autocomplete !== "off" &&
                inp.autocomplete !== "new-password" &&
                inp.autocomplete !== "current-password") {
                (0, finding_1.emit)({
                    type: "finding",
                    severity: "LOW",
                    category: "vulnerabilities",
                    title: `Password field allows browser autocomplete`,
                    detail: `Input "${inp.name}" in form (action: ${form.action}) has autocomplete="${inp.autocomplete ?? "unset"}".`,
                    fix: 'Set autocomplete="new-password" on registration fields and autocomplete="current-password" on login fields.',
                });
            }
        }
    }
    if (forms.length > 0) {
        (0, finding_1.status)(`Crawler: analysed ${forms.length} form(s).`);
    }
}
