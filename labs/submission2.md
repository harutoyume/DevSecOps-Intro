# Lab 2 Submission: Threat Modeling with Threagile

**Student:** Ilsaf Abdulkhakov
**Date:** February 14, 2026  
**Lab:** Threat Modeling with Threagile

---

## Task 1: Baseline Threat Model Analysis

### 1.1 Risk Ranking Methodology

Risks were prioritized using a composite scoring system to objectively rank threats by their overall severity:

**Composite Score Formula:** `Severity * 100 + Likelihood * 10 + Impact`

**Scoring Mappings:**
- **Severity:** critical (5), elevated (4), high (3), medium (2), low (1)
- **Likelihood:** very-likely (4), likely (3), possible (2), unlikely (1)
- **Impact:** high (3), medium (2), low (1)

### 1.2 Top 5 Identified Risks

| Rank | Risk Title | Severity | Category | Asset | Likelihood | Impact | Composite Score |
|------|-----------|----------|----------|-------|------------|--------|-----------------|
| 1 | **Unencrypted Communication** (Direct to App) transferring authentication data | Elevated | unencrypted-communication | user-browser | likely | high | **433** |
| 2 | **Missing Authentication** (Reverse Proxy -> Juice Shop) | Elevated | missing-authentication | juice-shop | likely | medium | **432** |
| 3 | **Cross-Site Scripting (XSS)** at Juice Shop Application | Elevated | cross-site-scripting | juice-shop | likely | medium | **432** |
| 4 | **Unencrypted Communication** (Reverse Proxy -> App) | Elevated | unencrypted-communication | reverse-proxy | likely | medium | **432** |
| 5 | **Cross-Site Request Forgery (CSRF)** via Direct Access | Medium | cross-site-request-forgery | juice-shop | very-likely | low | **241** |

### 1.3 Critical Security Concerns Analysis

**1. Unencrypted Communication (Highest Risk - Score 433)**
The most critical risk identified is the unencrypted HTTP communication channel between the User Browser and Juice Shop Application. This communication transfers sensitive authentication data including session identifiers, credentials, and JWT tokens.
- **Attack Vector:** Man-in-the-middle (MITM) attacks to intercept plaintext HTTP traffic.
- **Impact:** Confidential user data exposure and account takeover.

**2. Missing Authentication Between Components (Score 432)**
The communication link from the Reverse Proxy to the Juice Shop Application lacks authentication mechanisms.
- **Attack Vector:** If the host or reverse proxy is compromised, an attacker could establish unauthorized connections to the backend application.
- **Impact:** Unauthorized access to application functionality.

**3. Cross-Site Scripting Vulnerability (Score 432)**
The Juice Shop application is vulnerable to XSS attacks, allowing malicious scripts to be injected and executed in user browsers.
- **Attack Vector:** Injection of malicious JavaScript through user-controllable inputs.
- **Impact:** Session token theft and account takeover.

**4. Internal Unencrypted Communication (Score 432)**
The connection between the Reverse Proxy and the Juice Shop Application uses HTTP internally.
- **Attack Vector:** Internal network sniffing if the host system is compromised.
- **Impact:** Exposure of authentication tokens in internal network segments.

**5. Cross-Site Request Forgery (Score 241)**
The application is susceptible to CSRF attacks where authenticated users can be tricked into performing unintended actions.
- **Attack Vector:** Malicious web pages triggering requests using the victim's active session.
- **Impact:** Unauthorized actions performed without user consent.

### 1.4 Diagram References

- **Data Flow Diagram:** `labs/lab2/baseline/data-flow-diagram.png`
- **Data Asset Diagram:** `labs/lab2/baseline/data-asset-diagram.png`

---

## Task 2: HTTPS Variant & Risk Comparison

### 2.1 Specific Changes Made

The following modifications were applied to create the secure model variant (`labs/lab2/threagile-model.secure.yaml`):

| Component | Parameter | Baseline Value | Secure Value | Rationale |
|-----------|-----------|----------------|--------------|-----------|
| **User Browser -> Direct to App** | `protocol` | `http` | `https` | Encrypt authentication data in transit |
| **Reverse Proxy -> To App** | `protocol` | `http` | `https` | Encrypt internal communication |
| **Persistent Storage** | `encryption` | `none` | `transparent` | Enable at-rest encryption for database and logs |

### 2.2 Risk Category Delta Table

| Category | Baseline | Secure | Δ |
|---|---:|---:|---:|
| container-baseimage-backdooring | 1 | 1 | 0 |
| cross-site-request-forgery | 2 | 2 | 0 |
| cross-site-scripting | 1 | 1 | 0 |
| missing-authentication | 1 | 1 | 0 |
| missing-authentication-second-factor | 2 | 2 | 0 |
| missing-build-infrastructure | 1 | 1 | 0 |
| missing-hardening | 2 | 2 | 0 |
| missing-identity-store | 1 | 1 | 0 |
| missing-vault | 1 | 1 | 0 |
| missing-waf | 1 | 1 | 0 |
| server-side-request-forgery | 2 | 2 | 0 |
| **unencrypted-asset** | **2** | **1** | **-1** |
| **unencrypted-communication** | **2** | **0** | **-2** |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

### 2.3 Delta Run Explanation

**Observed Results and Analysis:**
1. **Unencrypted Communication Risks (-2):** Both unencrypted communication vulnerabilities were eliminated. By changing protocols to HTTPS for both direct browser access and internal proxy communication, man-in-the-middle attacks against authentication data are no longer feasible.
2. **Unencrypted Asset Risk (-1):** Enabling transparent encryption on Persistent Storage protected sensitive data at rest. This provides defense-in-depth against host-level storage compromise.
3. **Residual Risks:** Risks like XSS, CSRF, and missing authentication remain as they require application-level changes or additional security components (WAF, Vault) not addressed by encryption alone.

### 2.4 Diagram Comparison

- **Baseline:** Shows unencrypted HTTP connections (red indicators) for browser-to-app and proxy-to-app links.
- **Secure:** Shows encrypted HTTPS connections (green indicators) and an encrypted storage icon for Persistent Storage.
- **Reference:** Comparison between `labs/lab2/baseline/data-flow-diagram.png` and `labs/lab2/secure/data-flow-diagram.png`.
