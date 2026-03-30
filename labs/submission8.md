# Lab 8 Submission — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification (4 pts)

### 1.1: Image Setup and Local Registry

Successfully pulled `bkimminich/juice-shop:v19.0.0` and pushed it to a local registry running on `localhost:5001`.

**Digest Reference:**
```
localhost:5001/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5
```

Evidence: `labs/lab8/analysis/ref.txt`

### 1.2: Key Pair Generation

Generated a Cosign key pair for signing:
- Private key: `labs/lab8/signing/cosign.key` (password protected, not committed)
- Public key: `labs/lab8/signing/cosign.pub`

### 1.3: Image Signing and Verification

**Signing Output:**
Successfully signed the image using the private key with the following parameters:
- `--allow-insecure-registry` (local registry)
- `--tlog-upload=false` (no transparency log for local demo)
- Key: `labs/lab8/signing/cosign.key`

Evidence: `labs/lab8/signing/sign-output.txt`

**Verification Output:**
Successfully verified the signature using the public key:

```
Verification for localhost:5001/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

Evidence: `labs/lab8/analysis/original-verify-success.txt`

### 1.4: Tamper Demonstration

**Tamper Scenario:**
1. Replaced the `juice-shop:v19.0.0` tag with a `busybox:latest` image
2. The new digest after tampering: `sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6`

**Verification Results:**
- **Tampered image verification:** ❌ FAILED with "Error: no signatures found"
- **Original digest verification:** ✅ PASSED (signature still valid for original digest)

Evidence:
- `labs/lab8/analysis/ref-after-tamper.txt`
- `labs/lab8/analysis/tamper-verify-fail.txt`

### Analysis: How Signing Protects Against Tag Tampering

**Tag Tampering Protection:**
Image signing with Cosign protects against tag tampering by cryptographically binding the signature to the **content digest** (SHA-256 hash) of the image, not to the mutable tag. When we:

1. Sign an image, the signature is created for the specific digest (e.g., `sha256:772d62...`)
2. Replace the tag with a different image (busybox), the tag now points to a new digest
3. Verify the tampered image, Cosign finds no valid signature for the new digest

This demonstrates that **tags are mutable pointers** and cannot be trusted alone. The signature is tied to the immutable content hash.

**Subject Digest Meaning:**
The "subject digest" is the cryptographic hash (SHA-256) of the image manifest. It uniquely identifies the exact content of the container image, including all layers, metadata, and configuration. This digest is:
- **Immutable:** Any change to the image produces a different digest
- **Content-addressable:** The same content always produces the same digest
- **Tamper-evident:** Even a single byte change results in a completely different digest

By signing the digest rather than the tag, we ensure that:
- The signature verifies the exact content, not just a name
- Tag reuse attacks are prevented (attacker cannot reuse the tag for malicious content)
- The supply chain integrity is maintained through cryptographic proof

---

## Task 2 — Attestations: SBOM & Provenance (4 pts)

### 2.1: SBOM Attestation (CycloneDX)

**SBOM Generation:**
Reused the SBOM from Lab 4 (`labs/lab4/syft/juice-shop-syft-native.json`) and converted it to CycloneDX format for attestation.

**SBOM Statistics:**
- Format: CycloneDX JSON
- Total components: **3,532 packages**
- Target: `bkimminich/juice-shop:v19.0.0`

**Sample Components (first 3):**
1. `1to2@1.0.0` - NAN 1 -> 2 Migration Script (MIT)
2. `@adraffy/ens-normalize@1.10.1` - Ethereum Name Service Name Normalizer (MIT)
3. `@babel/helper-string-parser@7.27.1` - Babel utility package (MIT)

Evidence: `labs/lab8/attest/sbom-sample-components.json`

**Attestation Process:**
Attached the SBOM as a CycloneDX attestation to the signed image:

```bash
cosign attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"
```

**Verification:**
Successfully verified the SBOM attestation:

```
Verification for localhost:5001/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

The attestation payload contains the complete CycloneDX SBOM with all 3,532 components, their versions, licenses, and metadata.

Evidence: `labs/lab8/attest/verify-sbom-attestation.txt`

### 2.2: Provenance Attestation

**Provenance Predicate:**
Created a minimal SLSA Provenance v1 predicate:

```json
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {
    "parameters": {
      "image": "localhost:5001/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5"
    }
  },
  "metadata": {
    "buildStartedOn": "2026-03-30T16:23:39Z",
    "completeness": {"parameters": true}
  }
}
```

Evidence: `labs/lab8/attest/provenance.json`

**Attestation and Verification:**
Successfully attached and verified the provenance attestation.

**Decoded Payload:**
The in-toto statement envelope contains:
- `_type`: `https://in-toto.io/Statement/v0.1`
- `predicateType`: `https://slsa.dev/provenance/v0.2`
- `subject`: The image digest being attested
- `predicate`: The provenance metadata (builder, buildType, invocation, metadata)

Evidence: `labs/lab8/attest/provenance-decoded-fixed.json`

### Analysis: Attestations vs Signatures

**How Attestations Differ from Signatures:**

| Aspect | Signature | Attestation |
|--------|-----------|-------------|
| **Purpose** | Proves authenticity and integrity of the artifact itself | Proves claims **about** the artifact (metadata, provenance, SBOM) |
| **Content** | Signs the artifact's digest directly | Signs a structured statement (in-toto envelope) containing claims |
| **Use Case** | "This image is authentic and unmodified" | "This image was built by X, contains Y components, has Z properties" |
| **Format** | Simple signature over content | in-toto Statement with predicate types |
| **Verification** | `cosign verify` | `cosign verify-attestation` |

**What the SBOM Attestation Contains:**

The SBOM attestation provides a comprehensive inventory of all software components in the container image:

1. **Component Metadata:** Package names, versions, authors, descriptions
2. **Licensing Information:** License identifiers (MIT, Apache-2.0, etc.)
3. **Package URLs (purl):** Standardized identifiers for each component
4. **CPE Identifiers:** Common Platform Enumeration for vulnerability matching
5. **File Locations:** Where each component is located in the image layers
6. **Dependency Graph:** Relationships between components (not shown in sample)

For the juice-shop image, the SBOM contains **3,532 components**, primarily npm packages from the Node.js ecosystem. This allows:
- Vulnerability scanning against known CVE databases
- License compliance verification
- Supply chain risk assessment
- Dependency tracking and auditing

**What Provenance Attestations Provide:**

Provenance attestations provide **build metadata** that answers critical supply chain security questions:

1. **Builder Identity:** Who/what built the artifact (`student@local`)
2. **Build Type:** How it was built (`manual-local-demo`)
3. **Build Parameters:** Input parameters used in the build process
4. **Build Timestamp:** When the build occurred (`2026-03-30T16:23:39Z`)
5. **Completeness Indicators:** What metadata is complete vs incomplete
6. **Reproducibility:** Whether the build is reproducible

**Supply Chain Security Benefits:**
- **Traceability:** Track artifacts back to their build source
- **Auditability:** Verify that artifacts came from authorized builders
- **Policy Enforcement:** Enforce requirements (e.g., "only accept artifacts built by CI/CD")
- **Incident Response:** Quickly identify affected artifacts when a build system is compromised
- **SLSA Compliance:** Meet SLSA (Supply chain Levels for Software Artifacts) framework requirements

In production, provenance would include:
- Source repository and commit SHA
- CI/CD system details
- Build environment variables
- Materials (dependencies) used during build
- Complete reproducibility information

---

## Task 3 — Artifact (Blob/Tarball) Signing (2 pts)

### Artifact Creation and Signing

**Created Artifact:**
- File: `labs/lab8/artifacts/sample.tar.gz`
- Content: Text file with timestamp: `sample content Mon Mar 30 16:26:45 UTC 2026`

**Signing Process:**
Used Cosign's `sign-blob` command with bundle format:

```bash
cosign sign-blob \
  --yes \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
```

**Verification:**
Successfully verified the blob signature:

```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

Evidence:
- `labs/lab8/artifacts/sample.tar.gz.bundle`
- `labs/lab8/artifacts/verify-blob.txt`

### Analysis: Artifact Signing Use Cases and Differences

**Use Cases for Signing Non-Container Artifacts:**

1. **Release Binaries:**
   - CLI tools, executables, installers
   - Ensures users download authentic software from official sources
   - Example: Kubernetes releases, Terraform binaries, Homebrew packages

2. **Configuration Files:**
   - Kubernetes manifests, Helm charts, Terraform modules
   - Prevents malicious configuration injection
   - Ensures infrastructure-as-code integrity

3. **Documentation and Policies:**
   - Security policies, compliance documents
   - Provides non-repudiation for official documentation
   - Audit trail for policy changes

4. **Software Updates:**
   - Firmware updates, application patches
   - Critical for IoT devices and embedded systems
   - Prevents supply chain attacks via update mechanisms

5. **Build Artifacts:**
   - JAR files, Python wheels, npm packages
   - Ensures artifact integrity in artifact repositories
   - Supports reproducible builds verification

6. **Scripts and Automation:**
   - Deployment scripts, CI/CD pipeline definitions
   - Prevents unauthorized script modifications
   - Ensures execution of trusted automation

**How Blob Signing Differs from Container Image Signing:**

| Aspect | Container Image Signing | Blob Signing |
|--------|------------------------|--------------|
| **Target** | OCI image manifest (stored in registry) | Arbitrary file or tarball (stored anywhere) |
| **Storage** | Signature stored in OCI registry alongside image | Signature stored in separate bundle file or detached |
| **Reference** | Uses image digest (`sha256:...`) | Uses file path or hash |
| **Verification** | `cosign verify` with registry reference | `cosign verify-blob` with bundle or signature file |
| **Distribution** | Signature travels with image in registry | Signature must be distributed separately (bundle or detached) |
| **Format** | OCI registry API and manifest format | Simple file signature with bundle format |
| **Attestations** | Can attach attestations (SBOM, provenance) | Limited attestation support |
| **Ecosystem** | Integrated with container registries (Docker Hub, ECR, etc.) | Generic file signing, requires custom distribution |

**Key Differences:**

1. **Distribution Model:**
   - Container signing leverages OCI registry infrastructure
   - Blob signing requires separate signature distribution (bundle files, signature servers, etc.)

2. **Verification Workflow:**
   - Container: Pull image → verify signature automatically in registry
   - Blob: Download file → download signature/bundle → verify manually

3. **Metadata:**
   - Container signing includes rich metadata (layers, config, platform)
   - Blob signing is simpler (just file hash and signature)

4. **Use Case:**
   - Container signing is specialized for OCI images in registries
   - Blob signing is general-purpose for any file type

**Bundle Format Advantage:**
Using `--bundle` combines the signature and certificate into a single file, simplifying distribution. The bundle contains:
- The signature itself
- The signing certificate (if using keyless signing)
- Transparency log entry (if uploaded to Rekor)

This makes blob signing more portable and easier to verify without managing multiple files.

---

## Summary

### Completed Tasks

- ✅ **Task 1:** Local registry setup, image signing, verification, and tamper demonstration
- ✅ **Task 2:** SBOM attestation (3,532 components) and provenance attestation with payload inspection
- ✅ **Task 3:** Artifact (tarball) signing and verification using bundle format

### Key Learnings

1. **Digest-based Security:** Signing by digest (not tag) prevents tag reuse attacks and ensures immutable references
2. **Attestation Framework:** in-toto statements provide a standardized way to attach metadata (SBOM, provenance) to artifacts
3. **Supply Chain Transparency:** Attestations enable policy enforcement, auditability, and incident response
4. **Versatile Signing:** Cosign supports both container images (via registries) and arbitrary files (via bundles)

### Evidence Files

All outputs are saved under `labs/lab8/`:
- **Signing:** `labs/lab8/signing/` (keys, sign/verify outputs)
- **Analysis:** `labs/lab8/analysis/` (digest refs, verification results)
- **Attestations:** `labs/lab8/attest/` (SBOM, provenance, verification outputs)
- **Artifacts:** `labs/lab8/artifacts/` (blob signing demo)

### Production Considerations

For production use, the following changes would be necessary:

1. **Remove Insecure Flags:**
   - Remove `--allow-insecure-registry` (use HTTPS registries)
   - Remove `--tlog-upload=false` (upload to Rekor transparency log)
   - Remove `--insecure-ignore-tlog` (verify transparency log entries)

2. **Key Management:**
   - Use hardware security modules (HSM) or cloud KMS for key storage
   - Implement key rotation policies
   - Consider keyless signing with OIDC identity

3. **Policy Enforcement:**
   - Implement admission controllers (e.g., Kyverno, OPA Gatekeeper) to enforce signature verification
   - Require attestations (SBOM + provenance) for all production images
   - Define allowed signers and build systems

4. **Automation:**
   - Integrate signing into CI/CD pipelines
   - Automate SBOM generation and attestation
   - Generate provenance from build system metadata (GitHub Actions, GitLab CI, etc.)

5. **Monitoring:**
   - Monitor transparency logs for unauthorized signatures
   - Alert on verification failures
   - Track attestation compliance across the organization
