# SBOM Generation Context

This context defines the language used for SBOM assurance and represented software in meta-cyclonedx. It separates technical alignment from claims of conformance.

## Assurance

**Alignment profile**:
A versioned configuration that applies TR-03183-2 mappings and checks without asserting that the resulting SBOM conforms to the guideline.
_Avoid_: Compliance profile, conformance profile

**Profile baseline**:
The exact versions of TR-03183-2, the BSI CycloneDX property taxonomy, and the CycloneDX specification evaluated by an alignment profile.
_Avoid_: Latest standard

**Requirements matrix**:
The versioned mapping from each normative requirement in a profile baseline to its SBOM representation and validation verdict.
_Avoid_: Compliance checklist

**Alignment enforcement**:
The response to alignment findings: `report` produces results despite known gaps, while `strict` fails on machine-detectable violations or missing required assertions.
_Avoid_: Conformance mode

**Alignment report**:
A machine-processable account classifying requirements as verified, asserted, unmet, or unverifiable.
_Avoid_: Conformance certificate

**Conformance determination**:
The manufacturer’s conclusion based on the SBOM, alignment report, and completeness evidence unavailable to meta-cyclonedx.
_Avoid_: Generator certification

## Component model

**Primary component**:
The product described by an SBOM and the root of its dependency graph.
_Avoid_: Root package

**Delivery item**:
All software parts delivered with the primary component, whether created by its supplier or a third party; software obtained separately is excluded.
_Avoid_: Root filesystem

**Scope of delivery**:
The boundary separating components included in the delivery item from components that must be obtained separately.
_Avoid_: Runtime scope

**Logical component**:
An abstraction that groups multiple components so a product, application, framework, or operating system can be identified independently of its files.
_Avoid_: Recipe component, package component

**File component**:
A single executable file or archive represented as a component in its own right.
_Avoid_: Logical component, deployable

**Component instance**:
A separately represented occurrence of a logical component whose artifact, build, dependencies, or vulnerability status may differ from another occurrence.
_Avoid_: CVE alias

**Logical component identity**:
The creator-assigned name and version of an independently assessable component instance.
_Avoid_: Recipe name, CVE alias, filename

**Vulnerability correlation alias**:
A name and version used to match a logical component against a vulnerability source; multiple aliases do not create additional components.
_Avoid_: Component identity

**Artifact identity**:
The filename and cryptographic hash identifying an exact delivered file component.
_Avoid_: CPE, CVE product

**Build-time delivery-item SBOM**:
A build-generated SBOM that fully describes the primary component and components within the scope of delivery, and identifies each dependency path through its first component outside that scope.
_Avoid_: Runtime SBOM, logical-only SBOM

**Runtime package selection**:
A build-time filter that limits the SBOM to package metadata relevant to the target at runtime; it does not observe executing software.
_Avoid_: Runtime SBOM, runtime-only SBOM

## Responsibility and evidence

**Artifact inspection**:
Deterministic examination of delivered files for inventory, classification, and hashing, excluding inference of software dependencies from binary contents.
_Avoid_: Binary analysis, SCA

**SBOM creator**:
The entity responsible for compiling the information in the current SBOM.
_Avoid_: Generator tool

**Component creator**:
The entity that authored and, where applicable, maintains a component, independently of who supplies or distributes it.
_Avoid_: Product manufacturer, supplier

**Dependency completeness**:
The declared extent to which every required direct dependency or contained component has been enumerated for a component.
_Avoid_: Graph validity

## Licence roles

**Original licence**:
A licence assigned to a component by its creator.
_Avoid_: Distribution licence, effective licence

**Distribution licence**:
A licence under which the current component can be used by a recipient.
_Avoid_: Original licence, effective licence

**Effective licence**:
The licence under which the creator of the current SBOM uses a component.
_Avoid_: Original licence, distribution licence
