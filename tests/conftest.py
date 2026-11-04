import sys
from pathlib import Path

# The renderer module is shipped in the layer's lib directory and loaded by
# path from BitBake; tests import it directly through the same search path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
