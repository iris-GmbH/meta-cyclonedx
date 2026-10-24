# Cut over component identity globally

All generated SBOMs will stop treating CVE aliases as component names. The corrected separation of logical component, vulnerability-correlation, and artifact identities applies globally as a breaking change, without a legacy switch or profile-only model. Maintaining both models would duplicate graph, merge, VEX, and documentation semantics and perpetuate misleading default output.
