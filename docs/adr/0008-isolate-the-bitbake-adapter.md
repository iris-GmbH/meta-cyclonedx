# Isolate the BitBake adapter

BitBake-specific code will gather build and artifact facts and handle task integration, while a deep Python module will transform those facts into the SBOM, VEX, and alignment report through one small interface. Production and tests cross the same seam, concentrating identity, graph, mapping, and validation behavior outside the inline BitBake class.
