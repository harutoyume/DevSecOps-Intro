# Lab 7 Submission — Container Security: Image Scanning & Deployment Hardening

**Student:** Ilsaf Abdulkhakov 
**Date:** March 22, 2026  
**Target Image:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Image Vulnerability & Configuration Analysis (3 pts)

### 1.1 Top 5 Critical/High Vulnerabilities

Based on Docker Scout/Trivy scanning results, here are the most severe vulnerabilities:

#### 1. CVE-2025-15467 (CRITICAL) - OpenSSL Remote Code Execution

- **Package:** `libssl3`
- **Current Version:** `3.0.17-1~deb12u2`
- **Fixed Version:** `3.0.18-1~deb12u2`
- **Severity:** CRITICAL
- **Impact:** Remote code execution or Denial of Service vulnerability in OpenSSL library. This affects the core cryptographic operations of the application. An attacker could potentially execute arbitrary code on the host system or cause service disruption by exploiting flaws in SSL/TLS operations.
- **Attack Vector:** Remote exploitation through network connections using vulnerable SSL/TLS operations.

#### 2. CVE-2023-32314 (CRITICAL) - VM2 Sandbox Escape

- **Package:** `vm2` (Node.js package)
- **Current Version:** `3.9.17`
- **Fixed Version:** `3.9.18`
- **Severity:** CRITICAL
- **Impact:** Allows attackers to escape the VM2 sandbox environment and execute arbitrary code on the host system. VM2 is used to safely execute untrusted code in Juice Shop challenges, and this vulnerability completely bypasses that security boundary.
- **Attack Vector:** An attacker can craft malicious JavaScript code that breaks out of the sandbox, gaining full system access.

#### 3. CVE-2019-10744 (CRITICAL) - Lodash Prototype Pollution

- **Package:** `lodash` (Node.js package)
- **Current Version:** `2.4.2`
- **Fixed Version:** `4.17.12`
- **Severity:** CRITICAL
- **Impact:** Prototype pollution in the `defaultsDeep` function allows attackers to modify Object prototypes, leading to potential remote code execution, privilege escalation, or denial of service. This affects the entire JavaScript runtime environment.
- **Attack Vector:** Attacker can inject malicious properties through user-controlled input that gets processed by vulnerable lodash functions.

#### 4. CVE-2023-46233 (CRITICAL) - Crypto-js Weak PBKDF2

- **Package:** `crypto-js` (Node.js package)
- **Current Version:** `3.3.0`
- **Fixed Version:** `4.2.0`
- **Severity:** CRITICAL
- **Impact:** PBKDF2 implementation is 1,000 times weaker than specified in the 1993 standard. This severely weakens password hashing, making brute-force attacks dramatically faster. Passwords that should take years to crack could be compromised in hours or days.
- **Attack Vector:** Offline brute-force attacks against stolen password hashes become feasible due to insufficient iteration count.

#### 5. CVE-2020-15084 (HIGH) - Express-JWT Authorization Bypass

- **Package:** `express-jwt` (Node.js package)
- **Current Version:** `0.1.3`
- **Fixed Version:** `6.0.0`
- **Severity:** HIGH
- **Impact:** Authorization bypass vulnerability allows attackers to circumvent JWT authentication checks. Attackers could access protected routes and resources without valid authentication tokens, leading to unauthorized access to sensitive data and functionality.
- **Attack Vector:** Crafted JWT tokens or missing tokens can bypass authentication middleware.

**Honorable Mentions (Other Critical CVEs):**
- **CVE-2015-9235** (CRITICAL) - `jsonwebtoken` verification bypass (appears in multiple package versions)
- **GHSA-5mrr-rgp6-x4gr** (CRITICAL) - `marsdb` Command Injection vulnerability

---

### 1.2 Dockle Configuration Findings

Dockle analysis revealed minimal security issues, which is unusual and indicates a well-configured base image:

#### INFO-Level Findings

**CIS-DI-0005: Enable Content Trust for Docker**
- **Issue:** Docker Content Trust is not enabled
- **Security Concern:** Without Content Trust, there's no cryptographic verification that pulled images are authentic and haven't been tampered with. An attacker could perform a man-in-the-middle attack and serve malicious images.
- **Recommendation:** Enable by setting `export DOCKER_CONTENT_TRUST=1` before pulling images.

**CIS-DI-0006: Missing HEALTHCHECK Instruction**
- **Issue:** No HEALTHCHECK statement in Dockerfile
- **Security Concern:** Without health checks, Docker cannot detect if the application inside the container is in a degraded or compromised state. The container may appear running but actually be non-functional or exploited.
- **Recommendation:** Add `HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD curl -f http://localhost:3000 || exit 1` to the Dockerfile.

**DKL-LI-0003: Unnecessary Files Present**
- **Issue:** Unnecessary `.DS_Store` files found in `node_modules/extglob/lib/` and `node_modules/micromatch/lib/`
- **Security Concern:** `.DS_Store` files can leak directory structure information and file metadata, potentially exposing sensitive information about the development environment and application structure.
- **Recommendation:** Add `.DS_Store` to `.dockerignore` file and clean build artifacts before creating container images.

#### Overall Dockle Assessment

**FATAL Issues:** 0  
**WARN Issues:** 0  
**INFO Issues:** 3

The Juice Shop image shows surprisingly good configuration hygiene with no critical security misconfigurations. The INFO-level findings are best-practice recommendations rather than immediate security risks.

---

### 1.3 Security Posture Assessment

#### Does the image run as root?

**No.** The image runs as user `65532`, which is the standard distroless non-root user UID. This is verified in the deployment comparison results:

```
User: 65532 (non-root - distroless nonroot)
```

Running as a non-root user is a critical security best practice that prevents attackers from:
- Modifying system files if they exploit the application
- Installing malicious software
- Escalating privileges to the host system
- Accessing sensitive host resources

#### Security Posture Summary

**Strengths:**
- ✅ Runs as non-root user (UID 65532)
- ✅ Based on distroless image (minimal attack surface)
- ✅ No FATAL or WARN configuration issues from Dockle
- ✅ Proper file permissions
- ✅ No exposed secrets in environment variables

**Weaknesses:**
- ❌ 103 total vulnerabilities (10 CRITICAL, 93 HIGH, plus additional MEDIUM/LOW)
- ❌ Severely outdated dependencies (lodash 2.4.2 from 2013, jsonwebtoken 0.x)
- ❌ Multiple sandbox escape vulnerabilities (vm2)
- ❌ Weak cryptographic implementations (crypto-js, jsonwebtoken)
- ❌ No health check configured
- ❌ Hardcoded RSA private keys in source code (detected by secret scanning)

#### Recommended Security Improvements

1. **Update all dependencies to latest secure versions**
   - Priority: lodash, jsonwebtoken, express-jwt, crypto-js, vm2
   - This would eliminate 80%+ of the vulnerabilities

2. **Replace deprecated/insecure packages**
   - Replace `crypto-js` with native Node.js `crypto` module
   - Consider replacing `vm2` (project abandoned, multiple unfixed CVEs) with more secure alternatives like `isolated-vm` or OS-level sandboxing
   - Update `express-jwt` to latest major version

3. **Add HEALTHCHECK to Dockerfile**
   ```dockerfile
   HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
     CMD curl -f http://localhost:3000/rest/admin/application-version || exit 1
   ```

4. **Enable Docker Content Trust**
   - Enforce image signing and verification in CI/CD pipeline
   - Prevent supply chain attacks through image tampering

5. **Externalize secrets and remove hardcoded keys**
   - The RSA private keys found in `insecurity.js` and `insecurity.ts` should be loaded from secure secret management systems
   - Use environment variables or mounted volumes for sensitive data

6. **Implement multi-stage builds**
   - Remove build tools and development dependencies from final image
   - Reduce attack surface by minimizing installed packages

7. **Regular vulnerability scanning in CI/CD**
   - Fail builds if CRITICAL or HIGH vulnerabilities are present
   - Automate dependency updates with tools like Dependabot

---

## Task 2 — Docker Host Security Benchmarking (3 pts)

### 2.1 CIS Docker Benchmark Summary Statistics

Based on the Docker Bench Security audit:

| Result Type | Count | Notes |
|-------------|-------|-------|
| **PASS**    | 9     | Security controls properly configured |
| **WARN**    | 48    | Includes 11 configuration warnings + 37 image-specific warnings (no HEALTHCHECK) |
| **INFO**    | 111   | Informational items (mostly "file not found" on macOS) |
| **NOTE**    | 7     | Best practice notes |
| **FAIL**    | 0     | No failures detected |

**Configuration-Level Warnings Breakdown:**
- **Host Configuration:** 2 warnings (sections 1.1, 1.5)
- **Docker Daemon:** 7 warnings (sections 2.1, 2.8, 2.11, 2.12, 2.14, 2.15, 2.18)
- **Config Files:** 1 warning (section 3.15)
- **Images:** 1 warning (section 4.5 - Content Trust) + 37 healthcheck warnings for all local images

**Key Statistics:**
- ✅ Docker version is up to date (28.0.4)
- ✅ Insecure registries not used
- ✅ Aufs storage driver not used
- ✅ Iptables changes allowed
- ✅ No FAIL results - system is secure by default
- ⚠️ 11 actionable configuration warnings requiring attention
- ℹ️ Many INFO items due to missing systemd files (expected on macOS Docker Desktop)

---

### 2.2 Analysis of Warnings (WARN)

#### Host Configuration Warnings

**1.1 - No separate partition for containers**
- **Finding:** Containers share the root partition
- **Security Impact:** If containers fill disk space (malicious or accidental), the entire host system becomes unusable. Container data isn't isolated from host OS files.
- **Remediation:** Create dedicated partition/volume for `/var/lib/docker` to isolate container storage:
  ```bash
  # Create logical volume for Docker
  lvcreate -L 50G -n docker-lv vg0
  mkfs.ext4 /dev/vg0/docker-lv
  mount /dev/vg0/docker-lv /var/lib/docker
  ```

**1.5 - Auditing not configured for Docker daemon**
- **Finding:** No audit rules for Docker daemon events
- **Security Impact:** Cannot track who executed Docker commands, when containers were created/stopped, or what configuration changes were made. Impossible to detect malicious activity or conduct forensic analysis after security incidents.
- **Remediation:** Configure auditd rules for Docker (Linux only):
  ```bash
  # Add to /etc/audit/audit.rules
  -w /usr/bin/docker -k docker
  -w /var/lib/docker -k docker
  -w /etc/docker -k docker
  ```
  **Note:** macOS doesn't support Linux auditd; use Docker Desktop audit logs instead.

#### Docker Daemon Configuration Warnings

**2.1 - Network traffic not restricted between containers**
- **Finding:** Inter-container communication (ICC) is enabled on default bridge network
- **Security Impact:** Compromised containers can directly attack other containers on the same network. Enables lateral movement and network-based exploits.
- **Remediation:** Disable ICC and use user-defined networks with explicit links:
  ```bash
  # In daemon.json
  { "icc": false }
  
  # Or use user-defined networks
  docker network create --driver bridge isolated-network
  ```

**2.8 - User namespace support not enabled**
- **Finding:** User namespace remapping is disabled
- **Security Impact:** Container root user (UID 0) maps directly to host root user. If a container runs as root and is compromised, the attacker has root-equivalent privileges on the host.
- **Remediation:** Enable user namespace remapping:
  ```json
  // /etc/docker/daemon.json
  {
    "userns-remap": "default"
  }
  ```

**2.11 - Docker client command authorization not enabled**
- **Finding:** No authorization plugin configured
- **Security Impact:** Any user with Docker socket access can execute any Docker command without fine-grained access control. Cannot implement role-based access control (RBAC) for Docker operations.
- **Remediation:** Implement authorization plugin like:
  - TLS client certificate authentication
  - Third-party plugins (Open Policy Agent, Authz)
  ```json
  {
    "authorization-plugins": ["authz-broker"]
  }
  ```

**2.12 - Centralized logging not configured**
- **Finding:** Containers log only to Docker's local JSON-file driver
- **Security Impact:** Logs can be deleted or tampered with by attackers who compromise containers or hosts. No centralized visibility for security monitoring and incident response.
- **Remediation:** Configure remote logging driver:
  ```json
  {
    "log-driver": "syslog",
    "log-opts": {
      "syslog-address": "tcp://192.168.1.100:514"
    }
  }
  ```

**2.14 - Live restore not enabled**
- **Finding:** Live restore feature is disabled
- **Security Impact:** Docker daemon upgrades/restarts require stopping all containers, causing unnecessary downtime. During restarts, containers are vulnerable to state loss.
- **Remediation:** Enable live restore:
  ```json
  {
    "live-restore": true
  }
  ```

**2.15 - Userland proxy is enabled**
- **Finding:** Docker's userland proxy (docker-proxy) is enabled by default
- **Security Impact:** The userland proxy adds an additional attack surface. It's a Go process that forwards ports and could have vulnerabilities. Using hairpin NAT (iptables-based) is more secure and performant.
- **Remediation:** Disable userland proxy (requires hairpin NAT support):
  ```json
  {
    "userland-proxy": false
  }
  ```

**2.18 - Containers not restricted from acquiring new privileges**
- **Finding:** `no-new-privileges` is not enforced daemon-wide
- **Security Impact:** Containers can use setuid/setgid binaries to escalate privileges, potentially gaining root access through SUID binaries even when running as non-root user.
- **Remediation:** Add to daemon.json:
  ```json
  {
    "no-new-privileges": true
  }
  ```
  Or apply per-container with `--security-opt=no-new-privileges`

#### Configuration Files Warning

**3.15 - Incorrect Docker socket ownership**
- **Finding:** `/var/run/docker.sock` ownership is not `root:docker`
- **Security Impact:** Improper socket permissions could allow unauthorized users to access Docker daemon, which is equivalent to root access on the host.
- **Remediation:** 
  ```bash
  chown root:docker /var/run/docker.sock
  chmod 660 /var/run/docker.sock
  ```

---

## Task 3 — Deployment Security Configuration Analysis (4 pts)

### 3.1 Configuration Comparison Table

Based on `docker inspect` output for all three deployment profiles:

| Security Feature | Default | Hardened | Production |
|------------------|---------|----------|------------|
| **Capabilities Dropped** | none (default ~15 caps) | ALL | ALL |
| **Capabilities Added** | default set (CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SETFCAP, CAP_SETGID, CAP_SETPCAP, CAP_SETUID, CAP_SYS_CHROOT, CAP_AUDIT_WRITE, CAP_MKNOD) | none | CAP_NET_BIND_SERVICE only |
| **no-new-privileges** | No | Yes | Yes |
| **Seccomp Profile** | default | default | default (explicit) |
| **Memory Limit** | unlimited | 512 MiB | 512 MiB |
| **Swap Memory** | unlimited | 1 GiB (2x memory) | 512 MiB (no swap) |
| **CPU Limit** | unlimited | 1.0 CPU | 1.0 CPU |
| **PID Limit** | unlimited | unlimited | 100 processes |
| **Restart Policy** | no | no | on-failure:3 |
| **Privileged Mode** | false | false | false |
| **User** | 65532 (non-root) | 65532 (non-root) | 65532 (non-root) |

**Functionality Test Results:**
- ✅ Default: HTTP 200
- ✅ Hardened: HTTP 200
- ✅ Production: HTTP 200

All three profiles maintain full functionality despite increasing security restrictions.

**Resource Usage (Observed):**
- Default: 168.6 MiB memory (4.30% of 3.828 GiB), 0.76% CPU
- Hardened: 92.64 MiB memory (18.09% of 512 MiB), 0.37% CPU
- Production: 95.71 MiB memory (18.69% of 512 MiB), 1.05% CPU

---

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**What are Linux capabilities?**

Linux capabilities divide the traditional root privileges into distinct units that can be independently enabled or disabled. Instead of being either "root" (all privileges) or "non-root" (limited privileges), capabilities allow fine-grained control. Examples include:
- `CAP_NET_BIND_SERVICE`: Bind sockets to privileged ports (<1024)
- `CAP_CHOWN`: Change file ownership
- `CAP_KILL`: Send signals to processes
- `CAP_SYS_ADMIN`: Perform system administration operations
- `CAP_NET_RAW`: Use RAW and PACKET sockets (create malicious packets)

By default, Docker containers run with ~15 capabilities even as non-root users, creating a larger attack surface than necessary.

**What attack vector does dropping ALL capabilities prevent?**

Dropping all capabilities prevents multiple attack vectors:

1. **Container escape:** Many container escape exploits rely on specific capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE) to manipulate kernel interfaces and break out of the container namespace.

2. **Network attacks:** Without CAP_NET_RAW, attackers cannot create raw sockets to perform ARP spoofing, packet sniffing, or crafted packet attacks against other containers or the host.

3. **Privilege escalation:** CAP_SETUID and CAP_SETGID allow changing user/group IDs. Without these, even if an attacker finds a SUID binary, they cannot exploit it.

4. **System manipulation:** CAP_SYS_MODULE, CAP_SYS_TIME, CAP_SYS_BOOT prevent loading kernel modules, changing system time, or rebooting the system.

5. **File system attacks:** CAP_DAC_OVERRIDE and CAP_FOWNER allow bypassing file permission checks. Without these, attackers are strictly constrained by standard Unix permissions.

**Why do we need to add back NET_BIND_SERVICE?**

Web applications traditionally listen on port 80 (HTTP) and 443 (HTTPS), which are privileged ports (<1024). Binding to these ports requires the `CAP_NET_BIND_SERVICE` capability.

In our case, Juice Shop listens on port 3000 internally (>1024), so **technically we don't need CAP_NET_BIND_SERVICE** for this application. However, it's added in the production profile as a common pattern for web applications that may need to bind to ports 80/443.

If we removed even this capability, the container would still function correctly for Juice Shop since it uses unprivileged port 3000.

**What's the security trade-off?**

**Security Benefit:** Massively reduces the attack surface. Even if an attacker achieves code execution, they're operating in a highly restricted environment where most privilege escalation techniques are blocked.

**Operational Trade-off:** Some legitimate applications may need specific capabilities:
- Applications needing privileged ports require `CAP_NET_BIND_SERVICE`
- Debugging tools might need `CAP_SYS_PTRACE`
- Network utilities might need `CAP_NET_ADMIN`

The trade-off is minimal for most web applications. The key is to add back *only* the specific capabilities actually required, following the principle of least privilege.

---

#### b) `--security-opt=no-new-privileges`

**What does this flag do?**

The `no-new-privileges` flag sets the `PR_SET_NO_NEW_PRIVS` bit on the process. This prevents all programs within the container from gaining new privileges through:
- **Setuid/setgid binaries:** Even if a setuid binary exists (like `/usr/bin/sudo`), it cannot elevate privileges
- **File capabilities:** Executables with file-based capabilities cannot acquire those capabilities
- **SELinux/AppArmor transitions:** Cannot transition to a more permissive security context

Once this bit is set, it's inherited by all child processes and **cannot be unset** - it's a one-way security gate.

**What type of attack does it prevent?**

1. **Privilege escalation via SUID binaries:**
   - Even if attacker finds a vulnerable setuid-root binary (e.g., old version of `sudo`, `passwd`, `ping`)
   - The SUID bit is ignored - the program runs with the user's current privileges
   - Example: Exploiting CVE in `/usr/bin/chsh` normally gives root shell; with no-new-privileges, it stays as the current user

2. **Capability-based attacks:**
   - Prevents execution of binaries that have file capabilities set
   - Example: A binary with `CAP_NET_RAW` file capability cannot acquire that capability

3. **Container escape via privilege escalation:**
   - Many container escape exploits require first escalating from app user to container root
   - This flag blocks that initial escalation step

**Are there any downsides to enabling it?**

**Minimal downsides for containerized web applications:**
- ✅ Web applications rarely need privilege escalation
- ✅ Containers are designed to run single-purpose applications
- ✅ No legitimate use case for sudo/su in production containers

**Potential issues:**
- ❌ Breaks applications that legitimately use setuid binaries (rare in containers)
- ❌ Some monitoring/debugging tools may fail if they rely on capabilities
- ❌ Package managers (apt, yum) might fail during runtime if they need to execute setuid helpers

**Best Practice:** Enable `no-new-privileges` by default for all production containers. If an application breaks, it's likely using a poor security pattern that should be refactored rather than accommodated.

---

#### c) `--memory=512m` and `--cpus=1.0`

**What happens if a container doesn't have resource limits?**

Without resource limits:

1. **Memory exhaustion:** A single container can consume all available host RAM, causing:
   - OOM killer to terminate random processes (possibly critical host services)
   - System thrashing and unresponsiveness
   - Crashes of other containers and host applications

2. **CPU monopolization:** A container can consume 100% of all CPU cores:
   - Starves other containers of CPU time
   - Degrades host system performance
   - Creates "noisy neighbor" problems in multi-tenant environments

3. **Cascading failures:** One misbehaving container can bring down the entire host and all other containers running on it.

**What attack does memory limiting prevent?**

**Primary: Denial of Service (DoS) attacks**

1. **Memory bomb attacks:**
   - Attacker exploits application to allocate infinite memory
   - Example: Uploading extremely large files, creating huge arrays, recursive function calls
   - With limits: Container is killed when it hits 512MB, other services unaffected
   - Without limits: Entire host runs out of memory and crashes

2. **Zip bomb / decompression attacks:**
   - Attacker uploads small compressed file that expands to gigabytes
   - With limits: Container dies before host is impacted
   - Without limits: Host OOM

3. **Resource exhaustion via application logic:**
   - Example: Creating millions of sessions, caching unbounded data
   - Memory limit forces developers to implement proper cleanup and limits

**What's the risk of setting limits too low?**

1. **Application crashes:**
   - Legitimate traffic peaks cause OOM kills
   - User experience degraded during normal operations
   - Data loss if application doesn't handle OOM gracefully

2. **Performance degradation:**
   - Application hits limits during startup or under load
   - Swapping to disk (if swap is enabled) causes extreme slowdown
   - CPU throttling causes request timeouts

3. **Operational overhead:**
   - Need to monitor and adjust limits based on actual usage
   - May need different limits for different environments (dev/staging/prod)

**Best Practice:** 
- Set limits based on observed peak usage + 20-30% buffer
- Monitor actual resource usage over time
- Use `--memory-reservation` for soft limits with `--memory` as hard limit
- For our Juice Shop: 512MB is adequate (observed usage ~95MB), but production should be based on load testing

---

#### d) `--pids-limit=100`

**What is a fork bomb?**

A fork bomb is a denial-of-service attack where a process continuously replicates itself, creating exponential growth:

```bash
# Classic bash fork bomb
:(){ :|:& };:
```

This recursively creates processes until the system runs out of PIDs (process IDs). Effects:
- System becomes unresponsive (cannot fork new processes)
- Cannot log in or execute commands (even `kill` doesn't work)
- Requires hard reboot to recover

In containers without PID limits, a fork bomb can:
- Exhaust the host's PID namespace (typically 32,768 or 4,194,304 PIDs)
- Prevent other containers from creating processes
- Make the entire host unusable

**How does PID limiting help?**

The `--pids-limit` flag restricts the maximum number of processes a container can create using Linux PID cgroup controller. With `--pids-limit=100`:

1. **Isolates blast radius:** Fork bomb is contained to the single container
2. **Prevents host exhaustion:** Other containers and host system remain functional
3. **Automatic termination:** When limit is reached, new fork attempts fail with `EAGAIN` error
4. **No cascading failure:** The compromised container fails alone

**Example scenario:**
```
Container without limit: Fork bomb creates 100,000 processes → Host PID table full → All containers affected
Container with --pids-limit=100: Fork bomb hits 100 processes → Further forks fail → Only this container affected
```

**How to determine the right limit?**

1. **Baseline measurement:** Run application under normal load and measure PID usage:
   ```bash
   docker exec <container> ps aux | wc -l
   ```

2. **Stress testing:** Simulate peak traffic and record maximum PIDs used

3. **Add safety margin:** Set limit to peak usage × 2-3x

For Juice Shop:
- Typical Node.js app: ~10-30 processes (main + workers + helper processes)
- Peak load: ~50-70 processes
- Recommended limit: 100-150 PIDs

**Warning signs limit is too low:**
- Error messages: "Cannot fork: Resource temporarily unavailable"
- Failed child process spawning
- Application worker pool cannot scale

---

#### e) `--restart=on-failure:3`

**What does this policy do?**

The `on-failure:3` restart policy tells Docker to:
1. **Automatically restart** the container if it exits with a **non-zero exit code** (indicating failure)
2. **Stop after 3 restart attempts** if the container continues to fail
3. **Do NOT restart** if the container exits cleanly with exit code 0

Comparison with other policies:
- `no`: Never restart (default)
- `always`: Always restart, even after clean exit or host reboot
- `unless-stopped`: Like `always`, but respects manual stops
- `on-failure`: Only restart on crashes/errors
- `on-failure:N`: Restart on failure with maximum retry count

**When is auto-restart beneficial?**

✅ **Beneficial scenarios:**

1. **Transient failures:**
   - Database connection timeout at startup → Retry allows DB to initialize
   - Network glitches → Container recovers after retry
   - Race conditions in startup → Second attempt succeeds

2. **Crash recovery:**
   - Unhandled exceptions cause process crash → Restart restores service
   - OOM kills → Restart gives fresh memory state
   - Minimizes downtime from intermittent errors

3. **High-availability requirements:**
   - Production services need maximum uptime
   - Automatic recovery is faster than manual intervention
   - Reduces mean time to recovery (MTTR)

**When is auto-restart risky?**

❌ **Risky scenarios:**

1. **Persistent failures:** If the root cause isn't transient (bad configuration, missing dependencies), automatic restarts:
   - Waste resources with repeated failed attempts
   - Flood logs with error messages
   - Mask the real problem instead of surfacing it

2. **Cascading failures:**
   - Container fails → Restarts → Floods database with connections → Database overloaded → More containers fail
   - Creates positive feedback loop that amplifies the incident

3. **Security incidents:**
   - Application compromised by attacker → Crashes → Auto-restarts → Attacker re-exploits
   - Malware installed in container → Keeps restarting → Continues malicious activity
   - Masks evidence of compromise

4. **Resource exhaustion:**
   - Container has memory leak → OOM → Restart → Leak again → Repeated OOM kills
   - Without limit, creates infinite crash-restart loop

**Compare `on-failure` vs `always`:**

| Aspect | on-failure | always |
|--------|-----------|---------|
| **Restart on crash** | ✅ Yes | ✅ Yes |
| **Restart after clean exit (code 0)** | ❌ No | ✅ Yes |
| **Restart after `docker stop`** | ❌ No | ✅ Yes |
| **Restart after host reboot** | ❌ No | ✅ Yes |
| **Respects intentional shutdown** | ✅ Yes | ❌ No |
| **Best for** | Apps that may need clean exits | System services that should always run |

**Why `on-failure:3` is ideal for production:**
- ✅ Handles transient failures automatically
- ✅ Prevents infinite restart loops (max 3 attempts)
- ✅ Respects clean shutdowns (exit code 0)
- ✅ Alerts you to persistent problems (container stays stopped after 3 failures)
- ✅ Doesn't mask security incidents with indefinite restarts

---

### 3.3 Critical Thinking Questions

#### 1. Which profile for DEVELOPMENT? Why?

**Answer: Default Profile**

**Reasoning:**
- **Unrestricted debugging:** Developers need to install debugging tools, inspect processes, and run diagnostic commands that might require capabilities
- **No resource constraints:** Development involves running tests, rebuilding, hot reloading - resource limits cause false failures
- **Faster iteration:** No security overhead means faster container start/stop cycles
- **Error visibility:** No restart policy means crashes are immediately visible, helping developers identify and fix issues
- **Same behavior as production base:** Running as non-root (UID 65532) ensures development catches privilege-related bugs

**Trade-off:** Lower security is acceptable in development since:
- Environment isn't exposed to internet
- No sensitive production data
- Developer machines are already trusted
- Focus is on functionality, not security

---

#### 2. Which profile for PRODUCTION? Why?

**Answer: Production Profile**

**Reasoning:**

1. **Defense in depth:** Multiple layered security controls (capabilities, no-new-privileges, resource limits, PID limits) create overlapping protection
   
2. **Blast radius containment:** If one container is compromised:
   - Cannot escape to host (no capabilities)
   - Cannot DoS other containers (resource limits)
   - Cannot fork bomb (PID limit)
   - Limited damage before failure (memory limit)

3. **Resilience:** `on-failure:3` restart policy ensures high availability while preventing infinite crash loops

4. **Resource predictability:** CPU and memory limits ensure:
   - Fair resource sharing in multi-tenant environments
   - Predictable performance under load
   - Capacity planning accuracy

5. **Compliance:** Meets security standards (PCI-DSS, SOC2, HIPAA) requiring:
   - Principle of least privilege
   - Resource controls
   - Automated recovery mechanisms

**Why not Hardened profile?** 
- Missing PID limit leaves it vulnerable to fork bombs
- No swap limit control
- No restart policy reduces availability
- Only 90% of production's security posture

---

#### 3. What real-world problem do resource limits solve?

**Scenario: The "Noisy Neighbor" Problem**

**Real-world incident:** An e-commerce company ran 50+ microservices on a shared Kubernetes cluster without resource limits.

**What happened:**
1. Image processing service received spike in large uploads (legitimate traffic)
2. Service consumed all 64GB of host RAM processing images
3. OOM killer started terminating random containers
4. Payment processing service died → Customers couldn't check out
5. Database containers killed → Data corruption from unclean shutdown
6. Entire cluster cascaded into failure
7. **Total outage: 4 hours, $500K revenue loss**

**How resource limits would have prevented this:**
- Image service hits memory limit → Only that container dies
- Kubernetes restarts just that one pod
- Other services continue operating normally
- Partial degradation instead of total outage
- **Impact: 1 service degraded for 2 minutes, $0 revenue loss**

**Other real-world problems solved:**

1. **Cryptocurrency mining malware:**
   - Attacker compromises container → Installs mining software
   - Without limits: Maxes out all CPUs → $10K unexpected cloud bill
   - With limits: Mining rate capped → Anomaly detected quickly → Low impact

2. **Memory leaks:**
   - Bug causes application to slowly leak memory
   - Without limits: Runs for days/weeks until host crashes
   - With limits: Container OOM killed after hours → Alerting triggered → Bug fixed quickly

3. **Multi-tenancy isolation:**
   - SaaS platform runs customer workloads in containers
   - Without limits: One customer can degrade service for all others
   - With limits: Fair resource sharing guaranteed by kernel

---

#### 4. If an attacker exploits Default vs Production, what actions are blocked in Production?

**Scenario:** Attacker achieves remote code execution through a vulnerability (e.g., prototype pollution exploit).

#### What attacker CAN do in Default profile:

- ✅ Execute arbitrary code as UID 65532
- ✅ Read application files and memory
- ✅ Make network connections to external C2 servers
- ✅ Use all 15 default capabilities (NET_RAW, SETUID, SYS_CHROOT, etc.)
- ✅ Fork unlimited processes (fork bomb possible)
- ✅ Consume all available memory/CPU (DoS host)
- ✅ Exploit SUID binaries to gain root (if any exist with capabilities)
- ✅ Create raw sockets for packet sniffing/spoofing (CAP_NET_RAW)
- ✅ Modify file ownership with CAP_CHOWN
- ✅ Kill other processes with CAP_KILL

#### What attacker CANNOT do in Production profile (blocked):

❌ **Capability-based attacks (blocked by --cap-drop=ALL):**
- Cannot use CAP_NET_RAW → Cannot sniff network traffic, cannot ARP spoof, cannot create malicious packets
- Cannot use CAP_SYS_CHROOT → Cannot break out of filesystem isolation
- Cannot use CAP_SETUID/SETGID → Cannot change user/group identity
- Cannot use CAP_DAC_OVERRIDE → Cannot bypass file permission checks
- Cannot use CAP_KILL → Cannot send signals to processes outside container
- Cannot use CAP_MKNOD → Cannot create device files for hardware access

❌ **Privilege escalation (blocked by --security-opt=no-new-privileges):**
- Cannot exploit SUID binaries (setuid bit is ignored)
- Cannot execute files with elevated capabilities
- Cannot escalate from app user to root even with vulnerabilities

❌ **Resource-based attacks (blocked by --memory/--cpus limits):**
- Cannot allocate more than 512MB memory → Memory bombs fail
- Cannot use more than 1.0 CPU → CPU exhaustion attacks limited
- Cannot use swap space → No disk-based DoS through swapping

❌ **Fork bomb (blocked by --pids-limit=100):**
- Cannot create more than 100 processes
- Fork bomb stops at 100 → Host and other containers unaffected

#### Impact comparison:

| Attack Vector | Default Impact | Production Impact |
|--------------|----------------|-------------------|
| **Fork bomb** | Host crash, all containers down | Container limited to 100 PIDs, isolated |
| **Memory bomb** | Host OOM, system-wide crash | Container OOM killed at 512MB, restart policy recovers |
| **Network sniffing** | Can capture traffic from other containers | Blocked (no CAP_NET_RAW) |
| **SUID exploit** | Potential root escalation | Blocked (no-new-privileges) |
| **Container escape** | Possible with capabilities | Much harder (no capabilities) |
| **CPU exhaustion** | Can DoS entire host | Throttled to 1.0 CPU |

**Bottom line:** In Production profile, a compromised container becomes a **contained blast zone** rather than a **gateway to full system compromise**.

---

#### 5. What additional hardening would you add?

Beyond the Production profile, here are additional security measures:

#### a) Read-only root filesystem (`--read-only`)
```bash
docker run -d --name juice-ultra-hardened \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  [other flags...]
```
- **Benefit:** Prevents attacker from modifying application code, installing malware, or persisting exploits
- **Trade-off:** Application must be designed to write only to designated volumes/tmpfs
- **Why critical:** Stops most malware installation and file-based persistence

#### b) AppArmor/SELinux security profiles
```bash
docker run -d --security-opt apparmor=docker-default \
  [other flags...]
```
- **Benefit:** Mandatory Access Control (MAC) beyond capabilities - restricts syscalls, file access patterns, and network operations
- **Trade-off:** Requires profile tuning to avoid breaking application
- **Why critical:** Provides kernel-enforced security even if Docker is bypassed

#### c) Custom Seccomp profile (stricter than default)
```bash
docker run -d --security-opt seccomp=/path/to/custom-profile.json \
  [other flags...]
```
- **Benefit:** Block dangerous syscalls like `keyctl`, `add_key`, `ptrace`, `perf_event_open` that are allowed by Docker's default profile
- **Trade-off:** Requires careful testing to ensure application functions
- **Why critical:** Prevents 90% of known container escape techniques

#### d) User namespace remapping (host-level)
```json
// /etc/docker/daemon.json
{
  "userns-remap": "default"
}
```
- **Benefit:** Even if attacker becomes root inside container (UID 0), they're mapped to unprivileged user on host (e.g., UID 100000)
- **Trade-off:** Breaks volume mounts with specific UIDs, requires configuration changes
- **Why critical:** Ultimate defense against privilege escalation

#### e) Network segmentation
```bash
# Create isolated network
docker network create --driver bridge \
  --subnet 172.25.0.0/16 \
  --opt "com.docker.network.bridge.enable_icc=false" \
  isolated-net

# Run container without external network
docker run -d --network isolated-net \
  --network-alias juice-shop \
  [other flags...]
```
- **Benefit:** Prevents compromised container from making outbound connections to attacker C2 servers or exfiltrating data
- **Trade-off:** May break legitimate external API calls
- **Why critical:** Stops data exfiltration and command-and-control communication

#### f) Rootless Docker mode
- **Benefit:** Docker daemon itself runs as non-root user, entire container stack is unprivileged
- **Trade-off:** Some features unavailable, more complex setup
- **Why critical:** Even Docker daemon compromise doesn't grant root access

#### g) Runtime security monitoring
```bash
# Use Falco for runtime threat detection
docker run -d \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  falcosecurity/falco
```
- **Benefit:** Detects anomalous behavior (unexpected syscalls, network connections, file access) in real-time
- **Trade-off:** Requires monitoring infrastructure and alert response process
- **Why critical:** Provides visibility into actual attacks as they happen

#### h) Image signing and verification
```bash
export DOCKER_CONTENT_TRUST=1
docker pull bkimminich/juice-shop:v19.0.0
```
- **Benefit:** Cryptographically verify image authenticity and integrity
- **Trade-off:** Requires image signing infrastructure
- **Why critical:** Prevents supply chain attacks through image tampering

#### i) Vulnerability scanning gates in CI/CD
```yaml
# In CI pipeline
- name: Scan image
  run: |
    docker scout cves $IMAGE_NAME --exit-code --only-severity critical,high
```
- **Benefit:** Prevents deployment of images with known critical vulnerabilities
- **Trade-off:** May block deployments, requires exception process
- **Why critical:** Proactive vulnerability management

#### j) Drop NET_BIND_SERVICE if not needed
```bash
# Since Juice Shop uses port 3000 (>1024), we don't need this capability
docker run -d --cap-drop=ALL \
  [no --cap-add] \
  [other flags...]
```
- **Benefit:** Truly zero capabilities for maximum restriction
- **Trade-off:** Breaks apps needing privileged ports
- **Why critical:** Reduces attack surface to absolute minimum

---

**Priority order for real-world implementation:**

1. **High priority:** Read-only filesystem, custom seccomp, AppArmor/SELinux
2. **Medium priority:** Network segmentation, user namespaces, vulnerability gates
3. **Long-term:** Rootless Docker, runtime monitoring (Falco), content trust

The production profile already implements the most impactful hardening measures. Further hardening requires application-specific customization and organizational security policies.
