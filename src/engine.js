// engine.js
// OCR pipeline now runs HERE, not on the desktop - GPU/Ollama live on this
// machine. Mirrors electron/main.js's runPythonEngine exactly (same spawn
// pattern, same "parse first JSON object from stdout" contract) since
// backend/engine.py itself is an unmodified copy.
//
// ponytail: splitPdfToImages is a real implementation, unlike the desktop
// app's current main.js which calls a function of this name that's never
// defined anywhere in that file (dead reference - PDF upload there would
// throw). Fixed here since this is the one place that now needs it.
import { spawn } from "child_process";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = path.join(__dirname, "..", "backend");

function runPython(scriptName, args) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(BACKEND_DIR, scriptName);
    const py = spawn("python", [scriptPath, ...args]);
    let output = "";
    py.stdout.on("data", (data) => { output += data.toString(); });
    py.stderr.on("data", (data) => console.log(`[${scriptName}]`, data.toString().trim()));
    py.on("close", () => {
      try {
        const jsonStart = output.indexOf("{") === -1 ? output.indexOf("[") : output.indexOf("{");
        if (jsonStart === -1) throw new Error(`No JSON found in ${scriptName} output`);
        resolve(JSON.parse(output.substring(jsonStart)));
      } catch (err) {
        const preview = output.length > 500 ? `${output.slice(0, 500)}... [truncated, ${output.length} chars total]` : output;
        console.error(`Raw ${scriptName} output:`, preview);
        reject(new Error(`Failed to parse ${scriptName} output: ${err.message}`));
      }
    });
    py.on("error", reject);
  });
}

export function runEngine(imagePath) {
  return runPython("engine.py", [imagePath]);
}

export async function splitPdfToImages(pdfPath) {
  const paths = await runPython("split_pdf.py", [pdfPath]);
  return paths.map(p => ({ path: p, mimetype: "image/jpeg" }));
}

export function cleanupPages(pageFiles) {
  for (const p of pageFiles) {
    if (fs.existsSync(p.path)) fs.unlinkSync(p.path);
  }
}

// xlsx export only - csv/json are serialized directly in Node. Same
// runPython contract as runEngine: argv = [payloadPath, outputPath], script
// prints { success, path } (or { error }) to stdout; the caller already
// knows outputPath since it chose it.
export function runExportEngine(payloadPath, outputPath) {
  return runPython("exportengine.py", [payloadPath, outputPath]);
}
