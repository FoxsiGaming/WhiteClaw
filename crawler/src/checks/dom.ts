import { Page } from "playwright";
import { ScanConfig, emit, status } from "../models/finding";

const b64Re = /[A-Za-z0-9+/]{20,}={0,2}/g;
const jwtRe = /eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+/g;

/**
 * Mines the fully-rendered DOM for:
 * - HTML comments (may leak paths, credentials, debug info)
 * - Hidden inputs (JWT tokens, Base64 blobs, sensitive values)
 * - JWTs and Base64-encoded strings in inline scripts
 */
export async function analyzeDOM(page: Page, cfg: ScanConfig): Promise<void> {
  status("Crawler: mining rendered DOM for hidden artifacts...");

  const { comments, hiddenInputs, inlineScripts } = await page.evaluate(() => {
    const comments: string[] = [];
    const hiddenInputs: { name: string; value: string }[] = [];

    // Walk comment nodes across the entire document
    const walker = document.createTreeWalker(
      document.documentElement,
      NodeFilter.SHOW_COMMENT
    );
    let node: Node | null;
    while ((node = walker.nextNode())) {
      const txt = (node as Comment).textContent?.trim() ?? "";
      if (txt.length > 3) {
        comments.push(txt);
      }
    }

    // Collect hidden inputs
    document.querySelectorAll<HTMLInputElement>('input[type="hidden"]').forEach((el) => {
      if (el.value) {
        hiddenInputs.push({ name: el.name || el.id || "(unnamed)", value: el.value });
      }
    });

    // Inline script content (for JWT / Base64 scanning)
    const inlineScripts = Array.from(document.querySelectorAll("script:not([src])"))
      .map((s) => s.textContent ?? "")
      .join("\n");

    return { comments, hiddenInputs, inlineScripts };
  });

  // HTML comments
  for (const comment of comments) {
    emit({
      type: "finding",
      severity: "LOW",
      category: "ctf",
      title: "HTML comment in rendered DOM",
      detail: comment.length > 250 ? comment.slice(0, 250) + "..." : comment,
      fix: "Strip all HTML comments from production builds — they can leak credentials, paths, or logic.",
    });
  }

  // Hidden inputs — scan for JWTs and Base64
  for (const inp of hiddenInputs) {
    const jwtMatches = inp.value.match(jwtRe);
    if (jwtMatches) {
      try {
        const parts = jwtMatches[0].split(".");
        const header = JSON.parse(atob(parts[0] + "=="));
        const payload = JSON.parse(atob(parts[1] + "=="));
        const alg = (header.alg ?? "?") as string;
        emit({
          type: "finding",
          severity: alg.toUpperCase() === "NONE" ? "CRITICAL" : "HIGH",
          category: "ctf",
          title: `JWT in hidden input: "${inp.name}" (alg: ${alg})`,
          detail: `Header: ${JSON.stringify(header)}\nPayload: ${JSON.stringify(payload)}`,
          fix: "Do not store JWTs in hidden form fields. Use HttpOnly cookies. Never allow alg:none.",
        });
      } catch {
        emit({
          type: "finding",
          severity: "MEDIUM",
          category: "ctf",
          title: `JWT token in hidden input: "${inp.name}"`,
          detail: jwtMatches[0].slice(0, 100),
          fix: "Do not store JWTs in hidden form fields. Use HttpOnly cookies.",
        });
      }
      continue;
    }

    const b64Matches = inp.value.match(b64Re);
    if (b64Matches) {
      for (const match of b64Matches) {
        try {
          const decoded = atob(match);
          if (/[\x20-\x7e]{8,}/.test(decoded)) {
            emit({
              type: "finding",
              severity: "LOW",
              category: "ctf",
              title: `Base64 blob in hidden input: "${inp.name}"`,
              detail: `Encoded: ${match.slice(0, 60)}\nDecoded: ${decoded.slice(0, 120)}`,
              fix: "Base64 is reversible — do not use it to obscure sensitive data.",
            });
          }
        } catch {
          // not valid base64
        }
      }
    }

    // Flag any hidden input with a non-empty value for review
    if (!jwtMatches && !b64Matches) {
      emit({
        type: "finding",
        severity: "INFO",
        category: "ctf",
        title: `Hidden input field: "${inp.name}"`,
        detail: `value=${inp.value.slice(0, 120)}`,
        fix: "Never trust hidden-field values for security decisions — they are trivially tampered.",
      });
    }
  }

  // Inline scripts — scan for JWTs
  const jwtInScript = inlineScripts.match(jwtRe);
  if (jwtInScript) {
    emit({
      type: "finding",
      severity: "HIGH",
      category: "ctf",
      title: "JWT hardcoded in inline script",
      detail: jwtInScript[0].slice(0, 150) + (jwtInScript[0].length > 150 ? "..." : ""),
      fix: "Never hardcode JWT tokens in client-side JavaScript.",
    });
  }
}
