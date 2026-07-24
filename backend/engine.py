#engine.py

import sys
import json
import os
import io
import uuid
import time
from datetime import datetime
from PIL import Image, ImageEnhance
from ollama import Client

# --- SAFE TERMINAL LOGGER ---
def log_status(msg):
    print(f"🤖 [Qwen-VL Engine]: {msg}", file=sys.stderr, flush=True)

# --- DYNAMIC FILE PATHS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROMPT_FILE = os.path.join(BASE_DIR, "prompt.txt")

try:
    with open(PROMPT_FILE, "r", encoding="utf-8") as f:
        JSON_PROMPT = f.read().strip()
except Exception as e:
    log_status(f"❌ Error: prompt.txt not found in {BASE_DIR}")
    sys.exit(1)

# --- OLLAMA CONFIGURATION ---
MODEL = "qwen3-vl:4b-instruct-q4_K_M"
client = Client(timeout=600)

INFERENCE_OPTIONS = {
    "device": "gpu",
    "num_predict": 3000,
    "num_ctx": 8000,
    "temperature": 0.0,
}

def enhance_and_convert_image(img):
    """Increase contrast by 20% as per your logic."""
    if img.mode != "RGB":
        img = img.convert("RGB")
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(1.2)
    buffer = io.BytesIO()
    img.save(buffer, format="JPEG")
    return buffer.getvalue()

def extract_with_qwen(image_bytes):
    log_status(f"Sending image to {MODEL}...")
    
    response = client.generate(
        model=MODEL,
        prompt=JSON_PROMPT,
        images=[image_bytes],
        options=INFERENCE_OPTIONS,
        format="json" 
    )
    
    response_text = response.get("response", "{}").strip()
    
    try:
        return json.loads(response_text)
    except Exception:
        try:
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1
            return json.loads(response_text[start_idx:end_idx])
        except Exception:
            return {"raw_text": response_text}

def process_file(file_path):
    batch_id = str(uuid.uuid4())
    scan_time = datetime.now().isoformat()
    
    invoices = []
    
    try:
        log_status(f"Processing: {os.path.basename(file_path)}")
        im = Image.open(file_path)
        img_bytes = enhance_and_convert_image(im)
        
        extracted_data = extract_with_qwen(img_bytes)
        
        invoice_data = {
            "batch": batch_id,
            "datetime": scan_time,
            "name": os.path.basename(file_path),
            "status": "AI_PROCESSED",
            **extracted_data
        }
        invoices.append(invoice_data)
                
    except Exception as e:
        log_status(f"❌ Error: {e}")

    return {
        "batch_id": batch_id,
        "invoices": invoices,
        "invoice_count": len(invoices)
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
        
    try:
        result = process_file(sys.argv[1])
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)