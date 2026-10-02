import os
import sys

# Ensure repository root and individual module packages are in sys.path
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
for d in [
    ROOT_DIR,
    os.path.join(ROOT_DIR, "ai-engine"),
    os.path.join(ROOT_DIR, "custody"),
    os.path.join(ROOT_DIR, "correlation"),
    os.path.join(ROOT_DIR, "explainability"),
    os.path.join(ROOT_DIR, "backend")
]:
    if d not in sys.path:
        sys.path.insert(0, d)
