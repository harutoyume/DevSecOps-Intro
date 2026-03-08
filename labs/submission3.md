# Lab 3 Submission — Secure Git Practices

**Student:** Ilsaf Abdulkhakov  
**Date:** Feb 20, 2026  
**Lab:** Lab 3 — SSH Commit Signing & Pre-commit Secret Scanning

---

## Task 1 — SSH Commit Signature Verification (5 pts)

### 1.1 SSH Key Setup

**SSH Key Generation/Selection:**
- **Option used:** [ ] Option A - New ED25519 key  [x] Option B - Existing key
- **Key path:** `/Users/haru/.ssh/id_ed25519.pub`
- **Key fingerprint:**
  ```bash
  # Output of: ssh-keygen -lf /Users/haru/.ssh/id_ed25519.pub
  256 SHA256:OdhwyZMiZ3QCLYwvpB9GdcV4AifarkadEXz//C5lZqw ilsaftoday@gmail.com (ED25519)
  ```

**GitHub Configuration:**
- **Key added to GitHub:** [x] Yes  [ ] No
- **Key type:** Signing Key
- **Date added:** Feb 20, 2026

### 1.2 Git Configuration

**Git Signing Configuration:**
```bash
# Output of: git config --global --list | grep -E "(signingkey|gpgSign|gpg.format)"
user.signingkey=/Users/haru/.ssh/id_ed25519.pub
gpg.format=ssh
```

**Configuration breakdown:**
- `user.signingkey`: /Users/haru/.ssh/id_ed25519.pub
- `commit.gpgSign`: Enabled (manual -S or global config)
- `gpg.format`: ssh (SSH signing, not GPG)

### 1.3 Signed Commit Evidence

**Test Commit Creation:**
```bash
# Verification on GitHub confirms successful signing:
commit 8f5eede6f0b41da1236b6463767cf8e33f950297
Author: ilsaf <ilsaftoday@gmail.com>
Date:   Fri Feb 20 15:45:23 2026 +0300
test: verify SSH commit signing
```

**GitHub Verification:**
![GitHub Verified Badge](screenshots/verified-commit.png)

**Verification URL:** 
- GitHub commit link showing "Verified" badge: https://github.com/harutoyume/DevSecOps-Intro/commit/8f5eede6f0b41da1236b6463767cf8e33f950297

### 1.4 Security Analysis

**Benefits of SSH Commit Signing:**

1. **Authenticity Verification:**
   - Cryptographically proves the commit author's identity
   - Prevents commit impersonation attacks
   - Establishes non-repudiation (author cannot deny creating the commit)

2. **Supply Chain Security:**
   - Ensures code changes originate from verified developers
   - Protects against unauthorized code injection
   - Critical for compliance and audit trails

3. **Trust Boundaries:**
   - Establishes verifiable trust in collaborative environments
   - Enables policy enforcement (e.g., only accepting signed commits)
   - Provides defense against compromised developer accounts

**Why SSH Signing Critical in DevSecOps:**

Commit signing is critical because:
- **Prevents impersonation:** Attackers who compromise Git credentials cannot forge commits without the signing key
- **Supply chain integrity:** Signed commits create a verifiable chain of custody for code changes
- **Compliance requirements:** Many security standards (SOC 2, ISO 27001) require code provenance verification
- **Incident response:** Signed commits provide forensic evidence during security investigations

---

## Task 2 — Pre-commit Secret Scanning (5 pts)

### 2.1 Pre-commit Hook Setup

**Hook Installation:**
- **File path:** `.git/hooks/pre-commit`
- **Permissions:** `rwxr-xr-x` (executable)
- **Verification:**
  ```bash
  # Output of: ls -l .git/hooks/pre-commit
  -rwxr-xr-x@ 1 haru  staff  3347 Feb 20 15:40 .git/hooks/pre-commit
  ```

**Docker Environment:**
```bash
# Output of: docker --version
Docker version 28.0.4, build b8034c0

# Output of: docker images | grep -E "(trufflehog|gitleaks)"
trufflesecurity/trufflehog     latest      9a67b6d93148   14 hours ago    104MB
zricethezav/gitleaks           latest      691af3c7c5a4   2 months ago    76.6MB
```

### 2.2 Secret Detection Testing

#### Test 1: Blocked Commit (Secret Detected)

**Test scenario:** Attempt to commit a file containing realistic fake secrets (AWS, GitHub, Stripe, Private Key)

**Command executed:**
```bash
# test-secret.txt created with fake secrets
git add test-secret.txt
git commit -m "test: attempt to commit secret"
```

**Hook output:**
```bash
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: test-secret.txt
[pre-commit] Non-lectures files: test-secret.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-02-20T12:55:04Z    info-0  trufflehog      running source  {"source_manager_worker_id": "eVTvU", "with_units": true}
2026-02-20T12:55:04Z    info-0  trufflehog      finished scanning       {"chunks": 1, "bytes": 499, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "295.883083ms", "trufflehog_version": "3.93.4", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":290}}
Found unverified result 🐷🔑❓
Detector Type: Stripe
Decoder Type: PLAIN
Raw result: sk_live_********************************
Rotation_guide: https://howtorotate.com/docs/tutorials/stripe/
File: test-secret.txt
Line: 11
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning test-secret.txt with Gitleaks...
Gitleaks found secrets in test-secret.txt:
Finding:     stripe_key = sk_live_********************************
Secret:      sk_live_********************************
RuleID:      stripe-access-token
Entropy:     5.064869
File:        test-secret.txt
Line:        11
Fingerprint: test-secret.txt:stripe-access-token:11

Finding:     github_token = ghp_************************************
Secret:      ghp_************************************
RuleID:      generic-api-key
Entropy:     5.101345
File:        test-secret.txt
Line:        8
Fingerprint: test-secret.txt:generic-api-key:8

Finding:     -----BEGIN [REDACTED] PRIVATE KEY-----                                 
[REDACTED PRIVATE KEY CONTENT]
-----END [REDACTED] PRIVATE KEY-----                                                          
Secret:      -----BEGIN [REDACTED] PRIVATE KEY-----                                 
[REDACTED PRIVATE KEY CONTENT]
-----END [REDACTED] PRIVATE KEY-----                                                          
RuleID:      private-key
Entropy:     4.891713
File:        test-secret.txt
Line:        14
Fingerprint: test-secret.txt:private-key:14

12:55PM INF scanned ~499 bytes (499 bytes) in 31.4ms
12:55PM WRN leaks found: 3
---
✖ Secrets found in non-excluded file: test-secret.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: true
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

**Result:** [x] Commit blocked  [ ] Commit allowed  
**Evidence:** ![Commit Blocked](screenshots/commit-blocked.png)

#### Test 2: Successful Commit (No Secrets)

**Test scenario:** Commit a safe file without secrets (redacted documentation)

**Command executed:**
```bash
git add labs/submission3.md
git commit -S -m "docs: add lab3 secret scanning evidence"
```

**Hook output:**
```bash
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: labs/submission3.md
[pre-commit] Non-lectures files: labs/submission3.md
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning labs/submission3.md with Gitleaks...
[pre-commit] No secrets found in labs/submission3.md

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
[feature/lab3 f7d968f] docs: add lab3 secret scanning evidence
```

**Result:** [ ] Commit blocked  [x] Commit allowed  
**Evidence:** ![Success Commit](screenshots/success-commit.png)

#### Test 3: Lectures Directory Exception

**Test scenario:** Verify secrets in `lectures/` directory are allowed (educational content)

**Command executed:**
```bash
mkdir -p lectures/examples
cat > lectures/examples/intentional-secret.txt << 'EOF'
# Intentional example for education
GITHUB_TOKEN=ghp_exampleTokenForEducation123456789
EOF

git add lectures/examples/intentional-secret.txt
git commit -S -m "docs: add intentional secret example for lectures"
```

**Hook output:**
```bash
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: lectures/examples/intentional-secret.txt
[pre-commit] Non-lectures files: none
[pre-commit] Lectures files: lectures/examples/intentional-secret.txt
[pre-commit] Skipping TruffleHog (only lectures files staged)
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning lectures/examples/intentional-secret.txt with Gitleaks...
[pre-commit] No secrets found in lectures/examples/intentional-secret.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
[feature/lab3 18a11b8] docs: add intentional secret example for lectures
```

**Result:** [ ] Commit blocked  [x] Commit allowed with warning  
**Evidence:** ![Lectures Commit](screenshots/lectures-commit.png)

### 2.3 Security Analysis

**How Pre-commit Hooks Prevent Secret Leaks:**

1. **Shift-Left Security:**
   - Catches secrets before they enter version control
   - Prevents secrets from being pushed to remote repositories
   - Reduces remediation costs (cheaper to catch early than to rotate leaked secrets)

2. **Automated Detection:**
   - **TruffleHog:** Detects high-entropy strings and pattern-based secrets (API keys, tokens)
   - **Gitleaks:** Uses regex patterns to identify 140+ secret types (AWS keys, GitHub tokens, private keys)
   - Dual-tool approach reduces false negatives

3. **Developer Workflow Integration:**
   - Provides immediate feedback to developers
   - Prevents accidental commits (human error is the #1 cause of secret leaks)
   - Educational: teaches developers to recognize and avoid committing secrets

**Defense-in-Depth Strategy:**

Pre-commit hooks are one layer in a comprehensive secret management strategy:

| Layer | Tool/Practice | Purpose |
|-------|---------------|---------|
| **Local (Pre-commit)** | TruffleHog + Gitleaks | Block secrets before commit |
| **CI/CD** | GitHub Secret Scanning | Catch secrets missed locally |
| **Repository** | .gitignore, .env templates | Prevent sensitive files from staging |
| **Secrets Management** | HashiCorp Vault, AWS Secrets Manager | Secure storage and rotation |
| **Monitoring** | Git history audits | Detect historical leaks |

**Why Local + CI Scanning is Important:**

- **Local scanning:** Fast feedback, prevents mistakes before push
- **CI scanning:** Safety net for bypassed hooks (`git commit --no-verify`), enforces policy
- **Combined:** Defense-in-depth approach ensures secrets are caught at multiple checkpoints

**Real-World Impact:**

Secret leaks cause severe security incidents:
- **Uber (2016):** AWS credentials in GitHub led to 57M user records stolen
- **Toyota (2019):** Access key exposed for 5 years, affecting 3.1M customers
- **Codecov (2021):** Docker credential leak enabled supply chain attack

Automated secret scanning prevents these incidents by catching secrets before they become public.

---

## Challenges & Solutions

**Challenge 1:**
- **Issue:** The `mapfile` command used in the pre-commit hook script (initially from the lab description) failed on macOS.
- **Solution:** `mapfile` requires Bash 4.0+, but macOS default Bash is 3.2. I replaced `mapfile` with a more portable `while read` loop: `while IFS= read -r line; do STAGED+=("$line"); done < <(git diff --cached --name-only --diff-filter=ACM)`.

**Challenge 2:**
- **Issue:** Documentation containing fake secrets was blocked by the pre-commit hook when attempting to commit `submission3.md`.
- **Solution:** I redacted (masked) the secrets in the documentation (e.g., `sk_live_****` and `[REDACTED PRIVATE KEY]`) to prevent triggering the scanners while still showing the test results.

**Challenge 3:**
- **Issue:** Local `git log --show-signature` showed "No signature" despite the commit being signed.
- **Solution:** Local verification of SSH signatures requires a configured `allowedSignersFile`. However, verification on GitHub (which is the main goal) worked perfectly as the public key was uploaded as a "Signing Key".

---

## Key Takeaways

1. **Commit Signing:**
   - SSH commit signing is simpler than GPG and widely supported
   - Provides cryptographic proof of authorship for supply chain security
   - Essential for compliance and audit trails in DevSecOps workflows

2. **Secret Scanning:**
   - Pre-commit hooks provide immediate feedback to prevent secret leaks
   - Dual-tool scanning (TruffleHog + Gitleaks) improves detection coverage
   - Defense-in-depth requires multiple layers: local hooks, CI/CD scanning, and secrets management

3. **DevSecOps Culture:**
   - Security automation in development workflows reduces human error
   - Shift-left approach catches issues early when remediation is cheapest
   - Developer education through tooling builds security awareness
