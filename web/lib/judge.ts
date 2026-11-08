import { engine } from "./engine";
import type { Judgement, Report } from "./types";

const BASE = "https://generativelanguage.googleapis.com/v1beta/models";
export const DEFAULT_MODEL = "gemini-2.5-flash";

interface Requests {
  system: string;
  explain: string;
  jury: string;
  schema: unknown;
  votes: number;
}

type Answer = { text: string } | { error: string };

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function ask(key: string, model: string, system: string, prompt: string, schema?: unknown): Promise<Answer> {
  const generationConfig: Record<string, unknown> = { temperature: 1 };
  if (schema) {
    generationConfig.responseMimeType = "application/json";
    generationConfig.responseSchema = schema;
  }
  const body = JSON.stringify({
    systemInstruction: { parts: [{ text: system }] },
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig,
  });
  for (let wait = 2000; ; wait *= 2) {
    let res: Response;
    try {
      res = await fetch(`${BASE}/${encodeURIComponent(model)}:generateContent`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": key },
        body,
      });
    } catch {
      return { error: "Gemini request failed" };
    }
    if (res.ok) {
      const json = await res.json();
      const text = json?.candidates?.[0]?.content?.parts?.[0]?.text;
      return typeof text === "string" ? { text } : { error: "Gemini returned no text" };
    }
    if (![429, 500, 503].includes(res.status) || wait > 16000) return { error: `Gemini returned HTTP ${res.status}` };
    await pause(wait);
  }
}

export async function runJudge(
  report: Report,
  key: string,
  model: string,
  progress: (done: number, total: number) => void,
): Promise<Judgement> {
  const e = await engine();
  const json = JSON.stringify(report);
  const q: Requests = JSON.parse(e.judgeRequests(json));
  const total = 1 + q.votes;
  const answers: Answer[] = [];
  progress(0, total);
  answers.push(await ask(key, model, q.system, q.explain));
  progress(1, total);
  for (let i = 0; i < q.votes; i++) {
    answers.push(await ask(key, model, q.system, q.jury, q.schema));
    progress(answers.length, total);
  }
  return JSON.parse(e.judge(json, model, JSON.stringify(answers)));
}
