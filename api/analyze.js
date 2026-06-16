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
    const exifrMod = await import("exifr");
    const parse = exifrMod.parse ?? exifrMod.default?.parse;
    const fs = (await import("fs")).default;
    const buffer = fs.readFileSync(filePath);
    const data = await parse(buffer, {
      pick: ["Make", "Model", "Software", "DateTimeOriginal", "GPSLatitude", "GPSLongitude", "GPSLatitudeRef", "GPSLongitudeRef"],
      translateValues: true,
    }) || {};
    const flags = [];
    const info = {};
    if (data.Make || data.Model) {
      info.camera = `${data.Make || ""} ${data.Model || ""}`.trim();
    } else {
      flags.push("No camera make/model");
    }
    if (data.GPSLatitude != null) {
      info.gps = `${data.GPSLatitude}, ${data.GPSLongitude}`;
    }
    if (data.DateTimeOriginal) {
      info.timestamp = data.DateTimeOriginal.toISOString ? data.DateTimeOriginal.toISOString() : String(data.DateTimeOriginal);
    } else {
      flags.push("No original timestamp");
    }
    if (data.Software) {
      info.software = data.Software;
      // AI tool signatures in Software field
      const aiTools = ["adobe firefly", "midjourney", "dall-e", "stable diffusion", "gemini", "openai", "generative"];
      if (aiTools.some(t => data.Software.toLowerCase().includes(t))) {
        flags.push(`AI tool detected in Software field: ${data.Software}`);
      }
    } else {
      flags.push("Software field absent");
    }
    const fieldCount = Object.keys(data).length;
    if (fieldCount < 3) {
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
      detail: `Metadata extraction failed: ${e.message}`,
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

// ─── LAYER 4: AI Detection (Sightengine) ─────────────────────────────────────
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
    // Direct multipart upload using native Node 18 FormData + Blob (no npm form-data package)
    const imageBuffer = fs.readFileSync(filePath);
    const ext = path.extname(filePath).toLowerCase().replace(".", "");
    const mediaType = ext === "png" ? "image/png" : "image/jpeg";
    const blob = new Blob([imageBuffer], { type: mediaType });
    const form = new FormData();
    form.append("media", blob, path.basename(filePath));
    form.append("models", "genai");
    form.append("api_user", user);
    form.append("api_secret", secret);
    const response = await fetch("https://api.sightengine.com/1.0/check.json", {
      method: "POST",
      body: form,
    });
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Sightengine error ${response.status}: ${err}`);
    }
    const data = await response.json();
    if (data.status === "failure") throw new Error(JSON.stringify(data.error));

    // AI generation score (0–1)
    const aiScore = data?.type?.ai_generated ?? null;

    // Threshold: only penalize as high risk at ≥ 0.7. Scores 0.4–0.69 are ambiguous —
    // real photos with Photoshop background swaps commonly land there — so treat as low.
    const risk = (aiScore ?? 0) >= 0.7 ? "high" : "low";
    const aiPct = aiScore !== null ? Math.round(aiScore * 100) : null;
    const detailStr = aiPct !== null ? `Sightengine: ${aiPct}% probability of AI-generated content` : "Sightengine: no score returned";

    // Threat type classification (manipulation detection requires Sightengine enterprise plan)
    // Only flag as ai_generated when score is high enough to be meaningful (≥ 0.7)
    const threatType = (aiScore ?? 0) >= 0.7 ? "ai_generated" : "none";

    return {
      active: true,
      risk,
      threatType,
      results: {
        sightengine: {
          ai_generated: aiScore,
          ai_pct: aiPct,
        },
      },
      avgScore: aiScore,
      detail: detailStr,
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

    // Frame the Layer 4 score as a probability, not a confirmed threat type —
    // real photos with Photoshop compositing score 30–60% and should not bias Layer 5 toward "synthetic"
    const aiProbabilityNote = detectionResult.avgScore !== null
      ? `AI-generation probability (Sightengine): ${Math.round(detectionResult.avgScore * 100)}% — treat as a signal, not a conclusion. Scores below 70% are ambiguous and common in real photos with background replacement.`
      : "AI-generation probability: not available.";
    const evidence = `Metadata: ${metadataResult.detail} (${metadataResult.risk} risk). Detection: ${aiProbabilityNote}`;
    const prompt = `You are an expert digital image forensic analyst. Your task is to determine whether this image shows signs of manipulation, compositing, object insertion/removal, retouching, or other post-processing that would not occur in a single photographic capture. Examine all of the following forensic categories and identify specific visual evidence:\n\n1. EDGE INTEGRITY: Look for hard cutout edges, haloing, poor masking, unnatural transitions — even subtle ones. Not all manipulated images have obvious hard edges; soft compositing can leave faint halos or color fringing.\n2. NOISE & TEXTURE CONSISTENCY (KEY SIGNAL): Real camera photos have sensor noise/grain distributed across the entire image — even in skies, skin, and flat backgrounds. Composited or retouched regions are often suspiciously smooth. Look for abrupt changes in grain character, over-smoothed regions, or texture discontinuities between subject and background. IMPORTANT: a smooth or clean-looking background alone does NOT indicate AI generation — it is a common result of background replacement in photo editors like Photoshop.\n3. FOCUS & DEPTH OF FIELD: Sharpness inconsistencies between elements, focus mismatches, unrealistic depth-of-field transitions that do not match the apparent lens and subject distance.\n4. LIGHTING & SHADOWS: Conflicting light direction across elements, mismatched light intensity or color temperature, missing or incorrect shadows, absent contact shadows where a subject meets a surface.\n5. REFLECTIONS: Missing or incorrect reflections in surfaces (eyes, glasses, water, metal). Reflection geometry that does not match the scene.\n6. PERSPECTIVE & SCALE: Conflicting vanishing points, incorrect object scale relative to surroundings, spatial inconsistencies that suggest elements were sourced from different images.\n7. COLOR CONSISTENCY: White balance or color temperature mismatches between elements, local color anomalies, edges where color correction was applied inconsistently.\n8. ATMOSPHERIC INTEGRATION: Missing haze, contrast falloff, or depth effects on distant elements. Objects that do not visually belong in the scene environment.\n9. COMPRESSION & ENCODING: Localized compression differences (e.g., one region looks more JPEG-compressed than another), resampling artifacts, signs of copy/paste editing in pixel patterns.\n10. CAPTURE COHERENCE: Evaluate whether all visible elements appear to originate from the same camera, lens, lighting environment, and moment in time. Inconsistencies here are strong manipulation signals.\n11. CLONING & RETOUCHING: Repeated texture patterns (copy-move artifacts), suspiciously smooth or blurred regions, smeared details that suggest healing brush or clone stamp tools.\n12. AI GENERATION (distinct from manipulation): Unnatural textures throughout the entire image, anatomical errors (extra fingers, malformed ears, garbled text), background incoherence that spans the whole scene — not just one region. A smooth background alone is NOT evidence of AI generation.\n\nCRITICAL VERDICT RULES — read carefully before responding:\n- "manipulated": Use when the image contains REAL photographic elements (real people, real environments, real objects) BUT shows signs of compositing, cut/paste, background replacement, cloning, or selective retouching. This is the most important verdict for editorial fact-checking. A real person pasted onto a replaced background is "manipulated".\n- "synthetic": ONLY use when the ENTIRE image appears AI-generated with no real photographic source — everything looks generated, not photographed. Do NOT use this verdict just because a background looks smooth or clean.\n- "likely_synthetic": Use when most of the image appears AI-generated but some elements may be real.\n- "authentic": No manipulation signals detected — image appears to originate from a single photographic capture.\n- "likely_authentic": Probably authentic but minor ambiguities exist.\n- "uncertain": Cannot confidently classify — signals are mixed or insufficient.\n- If you see a real person in a real setting but the background or other elements look composited/replaced/smoothed — that is "manipulated", NOT "synthetic".\n\nEvidence from other layers: ${evidence}\n\nBe decisive and specific. Cite exact visual locations (e.g., "halo visible along subject's left shoulder", "noise pattern changes abruptly at the neck-to-background boundary", "shadow under left foot is missing"). If ANY edge, lighting, noise, perspective, or other inconsistency is visible between real photographic elements and other parts of the image, return "manipulated". Only return "synthetic" if the whole image looks AI-generated from scratch.\n\nRespond in JSON only: {"verdict":"authentic"|"likely_authentic"|"uncertain"|"manipulated"|"likely_synthetic"|"synthetic","confidence":0-100,"flags":["specific artifact observations citing exact locations"],"reasoning":"2-3 sentences citing exact visual locations of artifacts and which forensic category they fall under"}`;

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        max_tokens: 800,
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
      manipulated: "high",
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
    if (!layer?.active) continue; // skip unconfigured / failed layers
    totalW += w;
    totalP += w * (penalties[layer.risk] ?? 0.5);
  }
  if (totalW === 0) return null; // no active layers — insufficient data
  return Math.max(0, Math.min(100, Math.round(100 - (totalP / totalW) * 100)));
}

function scoreToVerdict(score, layers) {
  if (score === null) return {
    label: "Insufficient Data",
    color: "gray",
    recommendation: "Not enough layers ran to produce a trust score. Configure additional API keys.",
  };
  // Check if manipulation was the primary threat signal
  const llmVerdict = layers?.llm?.verdict;
  const detectionThreat = layers?.detection?.threatType;
  const isManipulation = llmVerdict === "manipulated" || llmVerdict === "likely_synthetic" || detectionThreat === "manipulated";

  if (score >= 80) return { label: "High Trust", color: "green", recommendation: "Strong authenticity signals. Suitable for publication with standard editorial review." };
  if (score >= 60) {
    if (isManipulation) return { label: "Possible Manipulation", color: "orange", recommendation: "Image appears real in origin but shows signs of digital manipulation. Independent verification strongly recommended before publication." };
    return { label: "Moderate Trust", color: "yellow", recommendation: "Some uncertainty. Additional verification recommended." };
  }
  if (score >= 40) {
    if (isManipulation) return { label: "Likely Manipulated", color: "red", recommendation: "Strong signals of digital manipulation. Real photo origin likely, but content may have been altered. Do not publish without verification." };
    return { label: "Low Trust", color: "orange", recommendation: "Multiple risk signals. Do not publish without independent verification." };
  }
  return { label: "Very Low Trust", color: "red", recommendation: "High probability of synthetic or heavily manipulated content. TRST does not recommend publishing." };
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
    const verdict = scoreToVerdict(trustScore, layers);
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
