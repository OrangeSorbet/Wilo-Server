import sys, json, fitz, os
from datetime import datetime

pdf_path = sys.argv[1]
out_dir = os.path.dirname(pdf_path)
doc = fitz.open(pdf_path)
pages = []
for i, page in enumerate(doc):
    pix = page.get_pixmap(dpi=200)
    out_path = os.path.join(out_dir, f"page-{i}-{datetime.now().timestamp()}.jpg")
    pix.save(out_path)
    pages.append(out_path)
print(json.dumps(pages))