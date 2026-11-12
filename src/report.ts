import type { Analysis, Outcome } from "./analyze.ts";

const MARK: Record<Outcome, string> = {
  ok: "✅",
  bypass: "🔓",
  permissive: "🟠",
  "false-reject": "⛔",
  crash: "💥",
  unsupported: "➖",
  lenient: "🟡",
  strict: "⚪",
};

export function markdownReport(a: Analysis): string {
  const names = a.adapters.map((x) => x.name);
  const lines: string[] = [];
  lines.push("# grimaldello results", "");
  lines.push(`Generated ${a.generatedAt}.`, "");
  lines.push("| Library | Language | Version |", "|---|---|---|");
  for (const x of a.adapters) lines.push(`| ${x.library} | ${x.language} | ${x.version} |`);
  lines.push("");
  const s = a.summary;
  lines.push(
    `${s.cases} cases. 🔓 security-relevant inputs accepted: **${s.securityBypasses}** · 🟠 malformed inputs accepted (hardening): **${s.permissive}** · ⛔ rejected but must accept: **${s.falseRejects}** · 💥 crashes: **${s.crashes}** · ⚠️ undocumented exceptions: **${s.unexpected}** · cases where libraries disagree: **${s.divergent}**`,
    "",
  );
  lines.push("Legend: ✅ follows the spec · 🔓 accepts a security-relevant input it must reject · 🟠 more permissive than the spec on a malformed input · ⛔ rejects a valid ceremony · 💥 crash · 🟡/⚪ accepts/rejects where the spec leaves a choice · ➖ algorithm not supported · ⚠️ rejected, but by throwing an exception type the library does not document (an application catching the documented one answers 500)", "");
  lines.push("Impact: **security** means an honest browser under attack can produce the input; **hardening** means only a modified client or authenticator can, affecting the attacker's own credential.", "");
  lines.push(`| Case | Impact | Expect | ${names.join(" | ")} |`, `|---|---|---|${names.map(() => "---").join("|")}|`);
  for (const c of a.cases) {
    const cells = names.map((n) => MARK[c.results[n].outcome] + (c.results[n].unexpected ? "⚠️" : ""));
    lines.push(`| \`${c.id}\`<br>${c.title} | ${c.impact} | ${c.expect} | ${cells.join(" | ")} |`);
  }
  lines.push("");
  const notable = a.cases.filter((c) => Object.values(c.results).some((r) => r.outcome === "bypass" || r.outcome === "permissive" || r.outcome === "false-reject" || r.outcome === "crash" || r.unexpected));
  if (notable.length) {
    lines.push("## Details", "");
    for (const c of notable) {
      lines.push(`### \`${c.id}\`: ${c.title}`, "", `Impact: ${c.impact}. Spec: ${c.spec}`, "");
      for (const n of names) {
        const r = c.results[n];
        lines.push(`- ${MARK[r.outcome]}${r.unexpected ? "⚠️" : ""} **${n}**: ${r.verdict}${r.error ? `: \`${r.error.replace(/`/g, "'").slice(0, 200)}\`` : ""}`);
      }
      lines.push("");
    }
  }
  return lines.join("\n");
}
