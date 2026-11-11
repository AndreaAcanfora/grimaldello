import type { Case, Expect } from "./cases.ts";

export interface Verdict {
  verdict: "accept" | "reject" | "unsupported" | "crash";
  error?: string;
  /** Rejected through an exception type the library does not document. */
  unexpected?: boolean;
}

export interface AdapterInfo {
  name: string;
  library: string;
  version: string;
  language: string;
}

export type Outcome =
  | "ok" // matches the specification
  | "bypass" // accepted something the specification says to reject
  | "false-reject" // rejected a valid ceremony
  | "crash"
  | "unsupported"
  | "lenient" // case with expect "either": accepted
  | "strict"; // case with expect "either": rejected

export interface CaseResult {
  id: string;
  title: string;
  category: string;
  ceremony: string;
  expect: Expect;
  spec: string;
  impact: string;
  results: Record<string, Verdict & { outcome: Outcome }>;
  divergent: boolean;
}

export interface Analysis {
  generatedAt: string;
  adapters: AdapterInfo[];
  cases: CaseResult[];
  summary: { cases: number; unexpected: number; securityBypasses: number; bypasses: number; falseRejects: number; crashes: number; divergent: number };
}

function outcome(expect: Expect, v: Verdict): Outcome {
  if (v.verdict === "crash") return "crash";
  if (v.verdict === "unsupported") return "unsupported";
  if (expect === "either") return v.verdict === "accept" ? "lenient" : "strict";
  if (expect === v.verdict) return "ok";
  return v.verdict === "accept" ? "bypass" : "false-reject";
}

export function analyze(cases: Case[], runs: { info: AdapterInfo; verdicts: Map<string, Verdict> }[]): Analysis {
  const out: CaseResult[] = cases.map((c) => {
    const results: CaseResult["results"] = {};
    for (const r of runs) {
      const v = r.verdicts.get(c.id) ?? { verdict: "crash", error: "no verdict" };
      results[r.info.name] = { ...v, outcome: outcome(c.expect, v) };
    }
    const verdicts = new Set(Object.values(results).filter((r) => r.verdict !== "unsupported").map((r) => r.verdict));
    return {
      id: c.id,
      title: c.title,
      category: c.category,
      ceremony: c.ceremony,
      expect: c.expect,
      spec: c.spec,
      impact: c.impact,
      results,
      divergent: verdicts.size > 1,
    };
  });
  const all = out.flatMap((c) => Object.values(c.results));
  return {
    generatedAt: new Date().toISOString(),
    adapters: runs.map((r) => r.info),
    cases: out,
    summary: {
      cases: out.length,
      securityBypasses: out.flatMap((c) => (c.impact === "security" ? Object.values(c.results) : [])).filter((r) => r.outcome === "bypass").length,
      bypasses: all.filter((r) => r.outcome === "bypass").length,
      falseRejects: all.filter((r) => r.outcome === "false-reject").length,
      unexpected: all.filter((r) => r.unexpected).length,
      crashes: all.filter((r) => r.outcome === "crash").length,
      divergent: out.filter((c) => c.divergent).length,
    },
  };
}
