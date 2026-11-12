#!/usr/bin/env node
// grimaldello generate   writes vectors/cases.jsonl
// grimaldello build [names] builds the adapters
// grimaldello run [names]   runs the adapters and writes results/

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCases, type Case } from "./cases.ts";
import { analyze, type AdapterInfo, type Verdict } from "./analyze.ts";
import { markdownReport } from "./report.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

interface AdapterSpec {
  name: string;
  cwd: string;
  build: string[];
  command: string[];
}

function loadSpecs(only: string[]): AdapterSpec[] {
  const specs = JSON.parse(readFileSync(join(ROOT, "adapters/adapters.json"), "utf8")) as AdapterSpec[];
  return only.length ? specs.filter((s) => only.includes(s.name)) : specs;
}

function build(only: string[]) {
  for (const spec of loadSpecs(only)) {
    process.stderr.write(`building ${spec.name}...\n`);
    const [cmd, ...args] = spec.build;
    const r = spawnSync(cmd, args, { cwd: join(ROOT, spec.cwd), stdio: "inherit" });
    if (r.status !== 0) throw new Error(`${spec.name}: build failed`);
  }
}

function generate(): Case[] {
  const cases = buildCases();
  const ids = new Set<string>();
  for (const c of cases) {
    if (ids.has(c.id)) throw new Error(`duplicate case id ${c.id}`);
    ids.add(c.id);
  }
  mkdirSync(join(ROOT, "vectors"), { recursive: true });
  writeFileSync(join(ROOT, "vectors/cases.jsonl"), cases.map((c) => JSON.stringify(c)).join("\n") + "\n");
  return cases;
}

function invoke(spec: AdapterSpec, input: string): { stdout: string; stderr: string; status: number | null } {
  const [cmd, ...args] = spec.command;
  const r = spawnSync(cmd, args, {
    cwd: join(ROOT, spec.cwd),
    input,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 300_000,
  });
  if (r.error) throw r.error;
  return { stdout: r.stdout, stderr: r.stderr, status: r.status };
}

function parseLines(stdout: string): Map<string, Verdict> {
  const out = new Map<string, Verdict>();
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("{")) continue;
    try {
      const v = JSON.parse(line) as Verdict & { id: string };
      if (v.id) out.set(v.id, { verdict: v.verdict, error: v.error, ...(v.unexpected ? { unexpected: true } : {}) });
    } catch {
      // not ours
    }
  }
  return out;
}

function runAdapter(spec: AdapterSpec, cases: Case[]): { info: AdapterInfo; verdicts: Map<string, Verdict> } {
  const infoRun = invoke({ ...spec, command: [...spec.command, "--info"] }, "");
  if (infoRun.status !== 0) throw new Error(`${spec.name} --info failed:\n${infoRun.stderr}`);
  const info = { name: spec.name, ...JSON.parse(infoRun.stdout.trim().split("\n").pop()!) } as AdapterInfo;

  const input = cases.map((c) => JSON.stringify(c)).join("\n") + "\n";
  const verdicts = parseLines(invoke(spec, input).stdout);
  // Anything missing crashed the adapter: retry those cases one by one so a
  // single crash does not hide the rest.
  for (const c of cases) {
    if (verdicts.has(c.id)) continue;
    const r = invoke(spec, JSON.stringify(c) + "\n");
    const v = parseLines(r.stdout).get(c.id);
    verdicts.set(c.id, v ?? { verdict: "crash", error: (r.stderr || `exit ${r.status}`).trim().split("\n").slice(-3).join(" | ").slice(0, 400) });
  }
  return { info, verdicts };
}

function run(only: string[]) {
  const cases = generate();
  const specs = loadSpecs(only);
  const results: { info: AdapterInfo; verdicts: Map<string, Verdict> }[] = [];
  for (const spec of specs) {
    process.stderr.write(`running ${spec.name}... `);
    const t = Date.now();
    try {
      results.push(runAdapter(spec, cases));
    } catch (e) {
      // Locally a missing toolchain should not stop the other libraries; in CI
      // every adapter must run.
      if (process.env.CI) throw e;
      process.stderr.write(`skipped (${(e as Error).message.split("\n")[0]})\n`);
      continue;
    }
    process.stderr.write(`${Date.now() - t} ms\n`);
  }
  const analysis = analyze(cases, results);
  mkdirSync(join(ROOT, "results"), { recursive: true });
  writeFileSync(join(ROOT, "results/results.json"), JSON.stringify(analysis, null, 2) + "\n");
  writeFileSync(join(ROOT, "results/RESULTS.md"), markdownReport(analysis));
  const s = analysis.summary;
  console.log(`${cases.length} cases × ${results.length} libraries: ${s.securityBypasses} security-relevant inputs accepted, ${s.permissive} malformed inputs accepted, ${s.falseRejects} rejected-but-must-accept, ${s.crashes} crashes, ${s.unexpected} undocumented exceptions, ${s.divergent} cases where libraries disagree`);
  console.log("results/RESULTS.md");
  // A baseline that a library rejects means the harness is wrong, not the
  // library: fail loudly so results built on it are not published.
  const broken = analysis.cases
    .filter((c) => c.category === "baseline")
    .flatMap((c) => Object.entries(c.results).filter(([, r]) => r.outcome !== "ok" && r.outcome !== "unsupported").map(([n, r]) => `${c.id} × ${n}: ${r.verdict} ${r.error ?? ""}`));
  if (broken.length) {
    console.error(`baseline cases failed, the harness is broken:\n${broken.join("\n")}`);
    process.exitCode = 1;
  }
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === "generate") {
  console.log(`${generate().length} cases → vectors/cases.jsonl`);
} else if (cmd === "build") {
  build(rest);
} else if (cmd === "run") {
  if (!existsSync(join(ROOT, "adapters/adapters.json"))) throw new Error("adapters/adapters.json not found");
  run(rest);
} else {
  console.error("usage: grimaldello generate | build [adapter...] | run [adapter...]");
  process.exit(2);
}
