# Limit artifact inspection to classification

The BSI-targeted path may inspect delivered files deterministically to inventory them, classify executable, archive, and structured properties, and calculate hashes. It will not infer dependencies from binary contents; dependency evidence remains the responsibility of build metadata and imported ecosystem BOMs. This supplies required file facts without turning meta-cyclonedx into a generic binary-analysis or SCA tool.
