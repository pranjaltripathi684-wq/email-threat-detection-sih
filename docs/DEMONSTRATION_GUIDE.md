# Academic Demonstration Guide & Scenario Script

This guide provides a structured walkthrough for demonstrating the **AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform** in academic defenses, technical reviews, or cybersecurity workshops.

---

## Quick Start: Starting the Platform

### Option 1: Local Monolith Execution (Zero Docker Dependencies)
1. **Start Backend Server:**
   ```bash
   cd backend
   python -m uvicorn app.main:app --port 8000 --reload
   ```
2. **Start Frontend Server:**
   ```bash
   cd frontend
   npm.cmd run dev
   ```
3. Open browser at: `http://localhost:5173`

### Option 2: Docker Compose Execution
```bash
docker compose up --build
```
Open browser at: `http://localhost`

---

## Authentication & Role Profiles

| Role | Username | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **Analyst** | `analyst` | `AnalystPass123!` | Uploads emails, reviews threat scores, adds case notes |
| **Administrator** | `admin` | `AdminPass123!` | Configures scoring thresholds, views audit logs |
| **Investigator** | `investigator` | `InvestigatorPass123!` | Reviews case timelines, correlates campaigns, exports reports |
| **Auditor** | `auditor` | `AuditorPass123!` | Performs cryptographic hash integrity audits |

---

## 5 Synthetic Demonstration Scenarios

Click **"Load Test Scenarios (A–E)"** in the top navigation bar to execute any test case with a single click:

### Scenario A: Lookalike-Domain Phishing (PayPal Deception)
- **Concept**: Adversary registers `paypa1-update.com` (homoglyph with digit `1`) and creates valid SPF/DKIM records to bypass naive spam filters.
- **Observed Threat Signals**:
  1. *Lookalike Domain Authentication Trap*: Flagged for passing authentication on a deceptive domain.
  2. *Deceptive Link Anchor*: Visible text says `https://www.paypal.com/...` while actual hyperlink points to `http://198.51.100.42/auth/...`.
  3. *Reply-To Redirection*: Reply-To points to external domain `collector-drop@anonym-drop.xyz`.
  4. *Urgency & Credential Cues*: Body demands password confirmation within 24 hours.
- **Expected Classification**: **Critical Threat (Score > 75/100)**.

### Scenario B: Executive Impersonation (CEO Fraud)
- **Concept**: Attacker configures display name as `"Dr. Arthur Vance, CEO & Executive Director"` but sends from public freemail (`exec.director.urgent@gmail.com`).
- **Observed Threat Signals**:
  1. *Freemail VIP Abuse*: Executive display name paired with a public Gmail domain.
  2. *Financial Request*: Requests emergency purchase of $2,500 Apple gift cards.
  3. *Confidentiality Pressure*: Demands strict confidentiality and bypassing phone verification.
  4. *Zero Malicious Attachments*: Illustrates detection of payload-less social engineering.
- **Expected Classification**: **High Risk / Suspicious (Score > 25/100)**.

### Scenario C: Business Email Compromise (BEC on Valid Domain)
- **Concept**: A legitimate partner domain (`legit-partner.com`) is compromised; SPF, DKIM, and DMARC all pass with full alignment.
- **Observed Threat Signals**:
  1. *Authentication Alignment*: SPF and DKIM pass for `legit-partner.com`.
  2. *Financial Wire Modification*: Email requests updating accounting routing numbers and bank accounts for an outstanding $48,500 invoice.
  3. *Behavioral Risk*: Demonstrates that the platform does not naively trust messages solely based on valid SPF/DKIM.
- **Expected Classification**: **Suspicious / BEC Category (Score > 25/100)**.

### Scenario D: Malicious Attachment (Double Extension)
- **Concept**: Fake subpoena email carrying an attachment named `Subpoena_Notice_Q3.pdf.exe`.
- **Observed Threat Signals**:
  1. *Double Extension Attack*: File ends in `.pdf.exe` to mislead recipient file managers.
  2. *PE Header Magic Bytes*: Detected Windows PE (`MZ`) executable header.
  3. *SPF & DMARC Failure*: Originating IP fails SPF verification.
  4. *Legal Intimidation Language*: Subpoena and court production keywords.
- **Expected Classification**: **Critical Threat (Score > 75/100)**.

### Scenario E: Legitimate Corporate Communication
- **Concept**: Benign internal sprint planning agenda.
- **Observed Threat Signals**:
  1. *Full DMARC Alignment*: SPF & DKIM pass and match visible From domain.
  2. *Matching Reply-To*: Fully aligned communication paths.
  3. *Encrypted Hops*: Full TLS encryption across transmission.
  4. *Clean Content*: No social engineering, credential harvesting, or deceptive links.
- **Expected Classification**: **Low Risk / Benign (Score < 20/100)**.

---

## Interactive Feature Walkthrough

1. **Relay Path Inspector (`Headers & Relay Path` tab)**: Step through intermediate SMTP hops, view time deltas between relays, and identify the highlighted *Earliest Reliable Public IP*.
2. **Geolocation Map (`Geolocation & Infra Map` tab)**: View the interactive Leaflet GIS map displaying hops, country flags, and autonomous system names with attribution disclaimers.
3. **Correlation Network (`Entity Correlation Graph` tab)**: Explore graph-connected entities (emails, domains, IPs, URLs, hashes) and review connected component clusters.
4. **Evidence & Chain of Custody (`Evidence & Custody Log` tab)**: Click **"Verify Cryptographic Integrity"** to trigger a real-time SHA-256 hash check of the physical file and log an immutable audit event.
5. **Formal Forensic Report (`Forensic Report Export` tab)**: Click **"Print / Export PDF Report"** to view and print the complete structured forensic report with executive summaries and legal disclaimers.
