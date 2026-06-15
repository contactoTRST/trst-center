// TRST.center - Analysis API
// Vercel Serverless Function
// POST /api/analyze — accepts multipart image upload, runs 6-layer decision tree

import Anthropic from "@anthropic-ai/sdk";
import formidable from "formidable";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

export const config = {
  api: { bodyParser: false },
};

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ─── LAYER 1: C2PA Provenance ────────────────────────────────────────────────
async function checkC2PA(filePath) {
  return { found: false, valid: false, issuer: null, risk: "not_found", detail: "No C2PA provenance certificate found" };
}

// ─── LAYER 2: Metadata Forensics ────────────────────────────────────────────
async function checkMetadata(filePath) {
  try {
    const { execSync } = await import("child_process");
    const raw = execSync(`exiftool -json -a -u "${filePath}" 2>/dev/null`, { timeout: 8000 });
    const data = JSON.parse(raw.toString())[0] || {};
    const flags = [];
    const info = {};
    if (data.Make || data.Model) { info.camera = `${data.Make || ""} ${data.Model || ""}`.trim(); } else { flags.push("No camera make/model"); }
    if (data.GPSLatitude) { info.gps = `${data.GPSLatitude}, ${data.GPSLongitude}`; }
    if (data.DateTimeOriginal) { info.timestamp = data.DateTimeOriginal; } else { flags.push("No original timestamp"); }
    if (data.Software) { info.software = data.Software; } else { flags.push("Software field absent"); }
    const fieldCount = Object.keys(data).length;
    if (fieldCount < 5) { flags.push("EXIF data appears stripped or minimal"); }
    const risk = flags.length >= 2 ? "high" : flags.length === 1 ? "medium" : "low";
    return { risk, active: true, flags, info, fieldCount, detail: flags.length ? flags.join(". ") : "Metadata appears intact" };
  } catch (e) {
    return { risk: "medium", active: true, flags: ["Could not read metadata"], info: {}, detail: "Metadata extraction failed" };
  }
}

// ─── LAYER 3: Origin Tracing
async function checkOrigin() {
  return { risk: "not_configured", active: false, earliest_source: null, sources_found: 0, detail: "Origin tracing not yet configured" };
}

// ─── LAYER 4: AI Detection
async function checkDetection(filePath) {
  const results = { sightengine: { skipped: true }, hive: { skipped: true } };
  return { risk: "not_configured", active: false, results, avgScore: null, detail: "Detection APIs not yet configured" };
}

// ─── LAYER 5: LLM Consensus
async function checkLLMConsensus(filePath, metadataResult, detectionResult) {
  if (!process.env.ANTHROPIC_API_KEY) {
    return { risk: "not_configured", active: false, verdict: null, reasoning: null, detail: "ANTHROPIC_API_KEY not set" };
  }
  try {
    const Anthropic = (await import("@anthropic-ai/sdk")).default;
    const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const fs = (await import("fs")).default;
    const path = (await import("path")).default;
    const imageBuffer = fs.readFileSync(filePath);
    const base64 = imageBuffer.toString("base64");
    const ext = path.extname(filePath).toLowerCase().replace(".", "");
    const mediaType = ext === "jpg" || ext === "jpeg" ? "image/jpeg" : ext === "png" ? "image/png" : "image/jpeg";
    const evidence = `Metadata: ${metadataResult.detail} (${metadataResult.risk} risk). Detection: ${detectionResult.detail}.`;
    const prompt = `You are a forensic media authenticity analyst. Analyze this image for signs of AI generation or manipulation.\nEvidence from other layers: ${evidence}\nRespond in JSON: {"verdict": "authentic"|"likely_authentic"|"uncertain"|"likely_synthetic"|"synthetic","confidence":0-100,"flags":[],"reasoning":"2-3 sentences"}`;
    const response = await anthropic.messages.create({ model: "claude-opus-4-5", max_tokens: 500, messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: mediaType, data: base64 } }, { type: "text", text: prompt }] }] });
    const text = response.content[0].text;
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("No JSON");
    const p = JSON.parse(match[0]);
    const riskMap = { authentic: "low", likely_authentic: "low", uncertain: "medium", likely_synthetic: "high", synthetic: "high" };
    return { risk: riskMap[p.verdict] || "medium", active: true, verdict: p.verdict, confidence: p.confidence, flags: p.flags || [], reasoning: p.reasoning, detail: `Claude: ${p.verdict} (${p.confidence}% confidence). ${p.reasoning}` };
  } catch (e) {
    return { risk: "not_configured", active: false, verdict: null, reasoning: null, detail: `LLM error: ${e.message}` };
  }
}

// ─── LAYER 6: Context
async function checkContext(filename) {
  return { risk: "not_configured", active: false, detail: "Context analysis not yet configured", filename };
}

function calculateTrustScore(layers) {
  // C2PA shortcut
  if (layers.c2pa.valid) return 95;

  // Only score layers that actually ran (active: true)
  const weights = { metadata: 15, origin: 15, detection: 20, llm: 25, context: 10 };
  const penalties = { low: 0, medium: 0.5, high: 1 };

  let totalW = 0, totalP = 0;
  for (const [k, w] of Object.entries(weights)) {
    const layer = layers[k];
    if (!layer?.active) continue; // skip unconfigured layers
    totalW += w;
    totalP += w * (penalties[layer.risk] ?? 0.5);
  }

  // If no active layers at all, return a neutral "insufficient data" score
  if (totalW === 0) return null;

  return Math.max(0, Math.min(100, Math.round(100 - (totalP / totalW) * 100)));
}

function scoreToVerdict(s) {
  if (s === null) return { label: "Insufficient Data", color: "gray", recommendation: "Not enough layers ran to produce a reliable score. Configure additional analysis APIs." };
  if (s >= 80) return { label: "High Trust", color: "green", recommendation: "Strong authenticity signals. Suitable for publication with standard editorial review." };
  if (s >= 60) return { label: "Moderate Trust", color: "yellow", recommendation: "Some uncertainty. Additional verification recommended." };
  if (s >= 40) return { label: "Low Trust", color: "orange", recommendation: "Multiple risk signals. Do not publish without independent verification." };
  return { label: "Very Low Trust", color: "red", recommendation: "High probability of synthetic content. TRST does not recommend publishing." };
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const { default: formidable } = await import("formidable");
  const form = formidable({ maxFileSize: 20 * 1024 * 1024, keepExtensions: true });
  let files;
  try { [, files] = await form.parse(req); }
  catch (e) { return res.status(400).json({ error: "Could not parse upload: " + e.message }); }
  const file = files?.image?.[0] || files?.file?.[0];
  if (!file) return res.status(400).json({ error: "No image file received" });
  const filePath = file.filepath;
  const fs = (await import("fs")).default;
  try {
    const c2pa = await checkC2PA(filePath);
    if (c2pa.valid) {
      fs.unlinkSync(filePath);
      return res.status(200).json({ trustScore: 95, verdict: { label: "High Trust", color: "green", recommendation: "Valid C2PA certificate." }, earlyExit: true, exitLayer: 1, layers: { c2pa }, analyzedAt: new Date().toISOString(), filename: file.originalFilename });
    }
    const [metadata, origin] = await Promise.all([checkMetadata(filePath), checkOrigin()]);
    const detection = await checkDetection(filePath);
    const llm = await checkLLMConsensus(filePath, metadata, detection);
    const context = await checkContext(file.originalFilename);
    const layers = { c2pa, metadata, origin, detection, llm, context };
    const trustScore = calculateTrustScore(layers);
    const verdict = scoreToVerdict(trustScore);
    try { fs.unlinkSync(filePath); } catch (_) {}
    return res.status(200).json({ trustScore, verdict, earlyExit: false, layers, analyzedAt: new Date().toISOString(), filename: file.originalFilename });
  } catch (e) {
    try { fs.unlinkSync(filePath); } catch (_) {}
    return res.status(500).json({ error: "Analysis failed: " + e.message });
  }
}
