// TRST.center — Analysis API (clean rewrite)
// POST /api/analyze — multipart image upload → 6-layer trust score

export const config = { api: { bodyParser: false } };

// Layer 1: C2PA
async function checkC2PA() {
  return { risk: 'unknown', found: false, valid: false, detail: 'No C2PA provenance certificate found' };
}

// Layer 2: Metadata
async function checkMetadata(filePath) {
  try {
    const { execSync } = await import('child_process');
    const raw = execSync(`exiftool -json -a -u "${filePath}" 2>/dev/null`, { timeout: 8000 });
    const data = JSON.parse(raw.toString())[0] || {};
    const flags = [];
    const info = {};
    if (data.Make || data.Model) { info.camera = (data.Make + ' ' + (data.Model || '')).trim(); }
    else { flags.push('No camera make/model'); }
    if (data.GPSLatitude) { info.gps = data.GPSLatitude + ', ' + data.GPSLongitude; }
    if (data.DateTimeOriginal) { info.timestamp = data.DateTimeOriginal; }
    else { flags.push('No original timestamp'); }
    if (data.Software) { info.software = data.Software; }
    else { flags.push('Software field absent'); }
    if (Object.keys(data).length < 5) { flags.push('EXIF data appears stripped or minimal'); }
    const risk = flags.length >= 2 ? 'high' : flags.length === 1 ? 'medium' : 'low';
    return { risk, flags, info, detail: flags.length ? flags.join('. ') : 'Metadata appears intact' };
  } catch (e) {
    return { risk: 'medium', flags: ['Could not read metadata'], info: {}, detail: 'Metadata extraction failed' };
  }
}

// Layer 3: Origin
async function checkOrigin() {
  return { risk: 'unknown', detail: 'Origin tracing not yet configured' };
}

// Layer 4: Detection
async function checkDetection() {
  return { risk: 'unknown', detail: 'Detection APIs not yet configured' };
}

// Layer 5: LLM
async function checkLLM(filePath, metadata, detection) {
  if (!process.env.ANTHROPIC_API_KEY) {
    return { risk: 'unknown', active: false, verdict: null, detail: 'ANTHROPIC_API_KEY not configured' };
  }
  try {
    const { default: Anthropic } = await import('@anthropic-ai/sdk');
    const { default: fs } = await import('fs');
    const { default: path } = await import('path');
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const buf = fs.readFileSync(filePath);
    const b64 = buf.toString('base64');
    const ext = path.extname(filePath).toLowerCase().slice(1);
    const mime = (ext === 'jpg' || ext === 'jpeg') ? 'image/jpeg' : ext === 'png' ? 'image/png' : 'image/webp';
    const prompt = [
      'You are a forensic media authenticity analyst.',
      'Analyze this image for signs of AI generation or manipulation.',
      'Context: metadata=' + metadata.detail + ', detection=' + detection.detail,
      'Reply ONLY with valid JSON (no markdown):',
      '{"verdict":"authentic"|"likely_authentic"|"uncertain"|"likely_synthetic"|"synthetic","confidence":0-100,"flags":["..."],"reasoning":"2-3 sentences"}'
    ].join('\n');
    const resp = await client.messages.create({
      model: 'claude-opus-4-5',
      max_tokens: 500,
      messages: [{ role: 'user', content: [
        { type: 'image', source: { type: 'base64', media_type: mime, data: b64 } },
        { type: 'text', text: prompt }
      ]}]
    });
    const match = resp.content[0].text.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('No JSON in response');
    const p = JSON.parse(match[0]);
    const riskMap = { authentic: 'low', likely_authentic: 'low', uncertain: 'medium', likely_synthetic: 'high', synthetic: 'high' };
    return {
      risk: riskMap[p.verdict] || 'medium',
      active: true,
      verdict: p.verdict,
      confidence: p.confidence,
      flags: p.flags || [],
      reasoning: p.reasoning,
      detail: 'Claude verdict: ' + p.verdict + ' (' + p.confidence + '% confidence). ' + p.reasoning
    };
  } catch (e) {
    return { risk: 'unknown', active: false, verdict: null, detail: 'LLM error: ' + e.message };
  }
}

// Layer 6: Context
async function checkContext(filename) {
  return { risk: 'unknown', detail: 'Context analysis not yet configured', filename };
}

// Scoring
function calcScore(layers) {
  if (layers.c2pa && layers.c2pa.valid) return 95;
  const weights = { metadata: 15, origin: 15, detection: 20, llm: 25, context: 10 };
  const penalties = { low: 0, medium: 0.5, high: 1, unknown: 0.3 };
  let tw = 0, tp = 0;
  for (const [k, w] of Object.entries(weights)) {
    tw += w;
    tp += w * (penalties[(layers[k] || {}).risk] ?? 0.3);
  }
  return Math.max(0, Math.min(100, Math.round(100 - (tp / tw) * 100)));
}

function scoreVerdict(s) {
  if (s >= 80) return { label: 'High Trust',      color: 'green',  recommendation: 'Strong authenticity signals. Suitable for publication with standard editorial review.' };
  if (s >= 60) return { label: 'Moderate Trust',  color: 'yellow', recommendation: 'Some uncertainty. Additional verification recommended.' };
  if (s >= 40) return { label: 'Low Trust',       color: 'orange', recommendation: 'Multiple risk signals. Do not publish without independent verification.' };
  return           { label: 'Very Low Trust',     color: 'red',    recommendation: 'High probability of synthetic content. TRST does not recommend publishing.' };
}

// Handler
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  let filePath = null;
  try {
    const { default: formidable } = await import('formidable');
    const form = formidable({ maxFileSize: 20 * 1024 * 1024, keepExtensions: true });
    const [, files] = await form.parse(req);
    const file = files?.image?.[0] || files?.file?.[0];
    if (!file) return res.status(400).json({ error: 'No image file received' });
    filePath = file.filepath;

    const [c2pa, metadata, origin] = await Promise.all([
      checkC2PA(),
      checkMetadata(filePath),
      checkOrigin(),
    ]);

    if (c2pa.valid) {
      return res.status(200).json({
        trustScore: 95,
        verdict: { label: 'High Trust', color: 'green', recommendation: 'Valid C2PA certificate present.' },
        earlyExit: true,
        layers: { c2pa, metadata, origin },
        analyzedAt: new Date().toISOString(),
        filename: file.originalFilename,
      });
    }

    const detection = await checkDetection();
    const llm       = await checkLLM(filePath, metadata, detection);
    const context   = await checkContext(file.originalFilename);

    const layers = { c2pa, metadata, origin, detection, llm, context };
    const trustScore = calcScore(layers);
    const verdict = scoreVerdict(trustScore);

    return res.status(200).json({
      trustScore, verdict, earlyExit: false,
      layers, analyzedAt: new Date().toISOString(),
      filename: file.originalFilename,
    });

  } catch (e) {
    return res.status(500).json({ error: e.message });
  } finally {
    if (filePath) {
      try { const { default: fs } = await import('fs'); fs.unlinkSync(filePath); } catch (_) {}
    }
  }
}
