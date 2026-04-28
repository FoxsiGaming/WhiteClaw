import { Page } from "playwright";
import { ScanConfig, emit, status } from "../models/finding";

interface InputInfo {
  name: string;
  type: string;
  autocomplete: string | null;
}

interface FormInfo {
  action: string;
  method: string;
  inputCount: number;
  hasCsrf: boolean;
  inputs: InputInfo[];
}

/**
 * Analyses rendered forms for missing CSRF tokens and insecure autocomplete
 * on password fields.  Runs after spaFetch so the DOM is fully rendered.
 */
export async function analyzeForms(page: Page, cfg: ScanConfig): Promise<void> {
  status("Crawler: analysing forms (CSRF, autocomplete)...");

  const forms: FormInfo[] = await page.evaluate(() => {
    const csrfKeys = ["csrf", "_token", "authenticity_token", "nonce", "xsrf"];

    return Array.from(document.querySelectorAll("form")).map((form) => {
      const inputs = Array.from(form.querySelectorAll("input")).map((inp) => ({
        name: inp.name || inp.id || "(unnamed)",
        type: inp.type || "text",
        autocomplete: inp.getAttribute("autocomplete"),
      }));

      const hasCsrf = inputs.some((i) =>
        csrfKeys.some((k) => i.name.toLowerCase().includes(k))
      );

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
      emit({
        type: "finding",
        severity: "HIGH",
        category: "vulnerabilities",
        title: `Form #${i + 1} missing CSRF token`,
        detail: `${form.method} form (action: ${form.action}) has no detectable CSRF token among ${form.inputCount} input(s).`,
        fix: "Add a synchroniser token or double-submit cookie CSRF defence to all state-changing forms.",
      });
    }

    for (const inp of form.inputs) {
      if (
        inp.type === "password" &&
        inp.autocomplete !== "off" &&
        inp.autocomplete !== "new-password" &&
        inp.autocomplete !== "current-password"
      ) {
        emit({
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
    status(`Crawler: analysed ${forms.length} form(s).`);
  }
}
