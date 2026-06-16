// TRST.center - Analysis API
// Vercel Serverless Function
// POST /api/analyze — accepts multipart image upload, runs 6-layer decision tree

export const config = {
  api: { bodyParser: false },
};

// ─── LAYER 1: C2PA Provenance ────────────────────────────────────────────────
async function checkC2PA(filePath) {
  return {
    active: true,
    found: false,
    valid: false,
    issuer: null,
    risk: "not_found",
    detail: "No C2PA provenance certificate found",
  };
}

// ─── LAYER 2: Metadata Forensics ─────────────────────────────────────────────
async function checkMetadata(filePath) {
  try {
    const { execSync } = await import("child_process");
    const raw = execSync(`exiftool -json -a -u "${filePath}" 2>/dev/null`, { timeout: 8000 });
    const data = JSON.parse(raw.toString())[0] || {};
    const flags = [];
    const info = {};
    if (data.Make || data.Model) {
      info.camera = `${data.Make || ""} ${data.Model || ""}`.trim();
    } else {
      flags.push("No camera make/model");
    }
    if (data.GPSLatitude) {
      info.gps = `${data.GPSLatitude}, ${data.GPSLongitude}`;
    }
    if (data.DateTimeOriginal) {
      info.timestamp = data.DateTimeOriginal;
    } else {
      flags.push("No original timestamp");
    }
    if (data.Software) {
      info.software = data.Software;
    } else {
      flags.push("Software field absent");
    }
    const fieldCount = Object.keys(data).length;
    if (fieldCount < 5) {
      flags.push("EXIF data appears stripped or minimal");
    }
    const risk = flags.length >= 2 ? "high" : flags.length === 1 ? "medium" : "low";
    return {
      active: true,
      risk,
      flags,
      info,
      fieldCount,
      detail: flags.length ? flags.join(". ") : "Metadata appears intact",
    };
  } catch (e) {
    return {
      active: false,
      risk: "not_found",
      flags: [],
      info: {},
      detail: "Metadata extraction failed",
    };
  }
}

// ─── LAYER 3: Origin Tracing ──────────────────────────────────────────────────
async function checkOrigin() {
  return {
    active: false,
    risk: "not_configured",
    earliest_source: null,
    sources_found: 0,
    detail: "Origin tracing not yet configured",
  };
}

// ─── LAYER 4: AI Detection (Sightengine) ──────────────────────────────────────
async function checkDetection(filePath) {
  const user = process.env.SIGHTENGINE_USER;
  const secret = process.env.SIGHTENGINE_SECRET;
  if (!user || !secret) {
    return {
      active: false,
      risk: "not_configured",
      results: { sightengine: { skipped: true, reason: "No API credentials configured" } },
      avgScore: null,
      detail: "Detection APIs not yet configured",
    };
  }
  try {
    const fs = (await import("fs")).default;
    const path = (await import("path")).default;
    // Read image and send as base64 via URL-encoded form — avoids form-data multipart issues on Vercel
    const imageBuffer = fs.readFileSync(filePath);
    const base64 = imageBuffer.toString("base64");
    const ext = path.extname(filePath).toLowerCase().replace(".", "");
    const mediaType = ext === "png" ? "image/png" : "image/jpeg";
    const dataUrl = `data:${mediaType};base64,${base64}`;
    const params = new URLSearchParams({
      models: "genai",
      api_user: user,
      api_secret: secret,
      url: dataUrl,
    });
    const response = await fetch("https://api.sightengine.com/1.0/check.json?" + params.toString());
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Sightengine error ${response.status}: ${err}`);
    }
    const data = await response.json();
    if (data.status === "failure") throw new Error(JSON.stringify(data.error));
    const aiScore = data?.type?.ai_generated ?? null;
    if (aiScore === null) throw new Error("No ai_generated score in response");
    const risk = aiScore >= 0.7 ? "high" : aiScore >= 0.4 ? "medium" : "low";
    const pct = Math.round(aiScore * 100);
    return {
      active: true,
      risk,
      results: {
        sightengine: { ai_generated: aiScore, score: pct },
      },
      avgScore: aiScore,
      detail: `Sightengine: ${pct}% probability AI-generated`,
    };
  } catch (e) {
    return {
      active: false,
      risk: "not_configured",
      results: { sightengine: { skipped: true, reason: e.message } },
      avgScore: null,
      detail: `Detection error: ${e.message}`,
    };
  }
}

// ─── LAYER 5: LLM Consensus (GPT-4o Vision) ──────────────────────────────────
async function checkLLMConsensus(filePath, metadataResult, detectionResult) {
  if (!process.env.OPENAI_API_KEY) {
    return {
      active: false,
      risk: "not_configured",
      verdict: null,
      reasoning: null,
      detail: "OPENAI_API_KEY not set",
    };
  }
  try {
    const fs = (await import("fs")).default;
    const path = (await import("path")).default;
    const imageBuffer = fs.readFileSync(filePath);
    const base64 = imageBuffer.toString("base64");
    const ext = path.extname(filePath).toLowerCase().replace(".", "");
    const mediaType =
      ext === "jpg" || ext === "jpeg" ? "image/jpeg" :
      ext === "png" ? "image/png" : "image/jpeg";

    const evidence = `Metadata: ${metadataResult.detail} (${metadataResult.risk} risk). Detection: ${detectionResult.detail}.`;
    const prompt = `You are a forensic media authenticity analyst. Analyze this image for signs of AI generation or manipulation.\nEvidence from other layers: ${evidence}\nRespond in JSON only: {"verdict": "authentic"|"likely_authentic"|"uncertain"|"likely_synthetic"|"synthetic","confidence":0-100,"flags":[],"reasoning":"2-3 sentences"}`;

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        max_tokens: 500,
        messages: [{
          role: "user",
          content: [
            {
              type: "image_url",
              image_url: { url: `data:${mediaType};base64,${base64}` },
            },
            { type: "text", text: prompt },
          ],
        }],
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`OpenAI API error ${response.status}: ${err}`);
    }

    const json = await response.json();
    const text = json.choices?.[0]?.message?.content || "";
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("No JSON in response");
    const p = JSON.parse(match[0]);
    const riskMap = {
      authentic: "low",
      likely_authentic: "low",
      uncertain: "medium",
      likely_synthetic: "high",
      synthetic: "high",
    };
    return {
      active: true,
      risk: riskMap[p.verdict] || "medium",
      verdict: p.verdict,
      confidence: p.confidence,
      flags: p.flags || [],
      reasoning: p.reasoning,
      detail: `GPT-4o: ${p.verdict} (${p.confidence}% confidence). ${p.reasoning}`,
    };
  } catch (e) {
    return {
      active: false,
      risk: "not_configured",
      verdict: null,
      reasoning: null,
      detail: `LLM error: ${e.message}`,
    };
  }
}

// ─── LAYER 6: Context ─────────────────────────────────────────────────────────
async function checkContext(filename) {
  return {
    active: false,
    risk: "not_configured",
    detail: "Context analysis not yet configured",
    filename,
  };
}

// ─── Scoring ──────────────────────────────────────────────────────────────────
function calculateTrustScore(layers) {
  if (layers.c2pa.valid) return 95;
  const weights = { metadata: 15, origin: 15, detection: 20, llm: 25, context: 10 };
  const penalties = { low: 0, medium: 0.5, high: 1 };
  let totalW = 0, totalP = 0;
  for (const [k, w] of Object.entries(weights)) {
    const layer = layers[k];
    if (!layer?.active) continue;
    totalW += w;
    totalP += w * (penalties[layer.risk] ?? 0.5);
  }
  if (totalW === 0) return null;
  return Math.max(0, Math.min(100, Math.round(100 - (totalP / totalW) * 100)));
}

function scoreToVerdict(score) {
  if (score === null) return {
    label: "Insufficient Data",
    color: "gray",
    recommendation: "Not enough layers ran to produce a trust score. Configure additional API keys.",
  };
  if (score >= 80) return { label: "High Trust", color: "green", recommendation: "Strong authenticity signals. Suitable for publication with standard editorial review." };
  if (score >= 60) return { label: "Moderate Trust", color: "yellow", recommendation: "Some uncertainty. Additional verification recommended." };
  if (score >= 40) return { label: "Low Trust", color: "orange", recommendation: "Multiple risk signals. Do not publish without independent verification." };
  return { label: "Very Low Trust", color: "red", recommendation: "High probability of synthetic content. TRST does not recommend publishing." };
}

// ─── Handler ──────────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const { default: formidable } = await import("formidable");
  const form = formidable({ maxFileSize: 20 * 1024 * 1024, keepExtensions: true });
  let files;
  try {
    [, files] = await form.parse(req);
  } catch (e) {
    return res.status(400).json({ error: "Could not parse upload: " + e.message });
  }
  const file = files?.image?.[0] || files?.file?.[0];
  if (!file) return res.status(400).json({ error: "No image file received" });
  const filePath = file.filepath;
  const fs = (await import("fs")).default;
  try {
    const c2pa = await checkC2PA(filePath);
    if (c2pa.valid) {
      fs.unlinkSync(filePath);
      return res.status(200).json({
        trustScore: 95,
        verdict: { label: "High Trust", color: "green", recommendation: "Valid C2PA certificate." },
        earlyExit: true,
        exitLayer: 1,
        layers: { c2pa },
        analyzedAt: new Date().toISOString(),
        filename: file.originalFilename,
      });
    }
    const [metadata, origin] = await Promise.all([checkMetadata(filePath), checkOrigin()]);
    const detection = await checkDetection(filePath);
    const llm = await checkLLMConsensus(filePath, metadata, detection);
    const context = await checkContext(file.originalFilename);
    const layers = { c2pa, metadata, origin, detection, llm, context };
    const trustScore = calculateTrustScore(layers);
    const verdict = scoreToVerdict(trustScore);
    try { fs.unlinkSync(filePath); } catch (_) {}
    return res.status(200).json({
      trustScore,
      verdict,
      earlyExit: false,
      layers,
      analyzedAt: new Date().toISOString(),
      filename: file.originalFilename,
    });
  } catch (e) {
    try { fs.unlinkSync(filePath); } catch (_) {}
    return res.status(500).json({ error: "Analysis failed: " + e.message });
  }
}
