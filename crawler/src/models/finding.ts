export interface ScanConfig {
  url: string;
  base_url: string;
  timeout?: number; // ms, default 30000
}

export interface Finding {
  type: "finding" | "status" | "error" | "done";
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category?: string;
  title?: string;
  detail?: string;
  fix?: string;
  message?: string;
}

export function emit(f: Finding): void {
  process.stdout.write(JSON.stringify(f) + "\n");
}

export function status(message: string): void {
  emit({ type: "status", message });
}

export function error(message: string): void {
  emit({ type: "error", message });
}

export function done(): void {
  emit({ type: "done" });
}
