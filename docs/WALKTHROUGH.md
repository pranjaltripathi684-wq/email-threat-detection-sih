# Walkthrough: AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

The academic prototype **"AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform"** has been designed, implemented, and verified across all 18 developmental phases.

---

## 1. Accomplished Deliverables

### A. Defensive Cybersecurity Architecture & Disclaimer Integrity
- Rigorously integrated calibrated forensic terminology throughout the backend, database models, reports, and UI:
  - *Probable sending infrastructure*
  - *Earliest reliable public IP*
  - *Estimated geolocation*
  - *Confidence-based assessment*
  - *Attribution support, not definitive attribution*
- Prominently displays legal and technical attribution limitations warning banners.

---

### B. Modular Backend Implementation (`backend/`)
- **FastAPI Core & Relational Schema**: 22+ relational tables (`users`, `cases`, `emails`, `email_headers`, `received_hops`, `authentication_results`, `urls`, `attachments`, `indicators`, `ip_enrichment`, `domain_enrichment`, `threat_intelligence_matches`, `campaigns`, `graph_entities`, `graph_relationships`, `evidence_items`, `custody_events`, `analyst_notes`, `alerts`, `audit_logs`, `model_predictions`, `system_settings`).
- **Cryptographic Evidence Preservation & Chain of Custody**: Safe ingestion of raw RFC 5322 byte streams, SHA-256 evidence hashing, and chronological audit event verification.
- **RFC 5322 Header & Relay Hop Parser**: Chronological reconstruction of intermediate SMTP hops, bogon/reserved IP classification, transit time delta calculations, and automated discovery of the *Earliest Reliable Public IP*.
- **Authentication & Alignment Matrix**: Evaluates SPF, DKIM, DMARC, ARC, and detects **Authentic Lookalike Traps** (where attackers configure valid DNS auth records on deceptive domains).
- **Homoglyph & Brand Typosquatting Analyzer**: Levenshtein edit distance, Jaro-Winkler similarity, Unicode/Punycode (`xn--`) detection, and target brand keyword matching.
- **Content & NLP Social Engineering Engine**: Scans for urgency, fear/authority, wire transfer/bank modifications, credential harvesting, and confidentiality pressure.
- **Machine Learning Pipeline**: Trained TF-IDF + calibrated Logistic Regression model returning predicted class probabilities and top contributing n-gram feature tokens.
- **Static URL & Attachment Forensics**: Inspects deceptive link anchors (`<a href="evil">legit</a>`), shorteners, IP-based destinations, high-entropy paths, double extensions (`.pdf.exe`), and macro signatures (`.docm`, VBA).
- **Explainable 7-Tier Risk Scoring Engine**: Weighted multi-vector scoring (0–100) with positive/mitigating evidence breakdown and actionable response recommendations.
- **NetworkX Correlation Graph**: Maps entity nodes and relationships, discovers connected campaign clusters, and computes centrality metrics.
- **Forensic Report Generator**: Generates formal HTML and printable PDF forensic intelligence reports complete with executive summaries, technical tables, and chain-of-custody records.

---

### C. Modern React Dashboard (`frontend/`)
- Built with React 18, TypeScript, Tailwind CSS, Lucide icons, and Leaflet maps.
- **15 Analyst Views**:
  1. **Overview Command Center**: Key metrics, risk distributions, recent alerts, and analyzed emails.
  2. **Ingest & Upload Email**: Drag-and-drop `.eml` upload, raw header/body paste, and scenario selector.
  3. **Threat Assessment**: Master risk score gauge (0–100), risk tier badge, and explainability breakdown.
  4. **Headers & Relay Path**: Interactive step-by-step relay hop timeline with time deltas and TLS status.
  5. **Auth & Alignment**: Table for SPF, DKIM, DMARC, ARC, and lookalike trap warnings.
  6. **URLs & Attachments**: Deceptive link anchor inspection and static attachment forensics.
  7. **Geolocation Map**: Interactive Leaflet GIS map with hop markers and attribution disclaimers.
  8. **Entity Correlation Graph**: Network topology canvas with identified campaign clusters.
  9. **Case Management**: Incident tracker, status updates, and timestamped analyst notes.
  10. **Evidence & Custody Log**: Real-time cryptographic SHA-256 hash validation and custody timeline.
  11. **Forensic Report Export**: Live preview and printable HTML/PDF report generator.
  12. **Threat Intelligence**: Indicator lookup (IP, domain, URL, hash) with reputation metrics.
  13. **User Directory & RBAC**: Separation of duties for Analyst, Admin, Investigator, and Auditor.
  14. **Audit Trail**: Non-repudiable immutable activity logs.
  15. **System Settings**: Configurable scoring weights, threshold sliders, and privacy policies.
- **Privacy Mode**: One-click analyst toggle to mask recipient PII across all views.

---

### D. Packaged Academic Demonstration Scenarios

| Scenario | Title | Key Forensic Signals | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **Scenario A** | Lookalike-Domain Phishing | Typosquatted domain `paypa1-update.com`, deceptive link anchor to IP destination, lookalike auth trap | **Critical / High Threat** |
| **Scenario B** | Executive Impersonation | CEO display name from public Gmail, $2,500 Apple gift card request, confidentiality pressure | **High Risk / Suspicious** |
| **Scenario C** | Business Email Compromise | Compromised partner domain `legit-partner.com` passing SPF/DKIM, requesting bank routing update | **Suspicious / BEC Category** |
| **Scenario D** | Malicious Attachment | Double extension `Subpoena_Notice_Q3.pdf.exe`, Windows PE (`MZ`) magic bytes, failed SPF | **Critical Threat** |
| **Scenario E** | Legitimate Message | Full DMARC pass, matching Reply-To, TLS encrypted hops, clean URLs | **Low Risk / Benign** |

---

## 2. Verification & Test Results

### 2.1 Automated Backend Test Suite
```bash
cd backend
python -m pytest tests/ -v
```
**Result**: **16 / 16 PASSED (100% Pass Rate)**
- `test_headers.py`: IP classification, text IP extraction, Received hop parsing, RFC 5322 message parsing.
- `test_auth.py`: SPF/DKIM/DMARC pass verification, lookalike domain trap detection.
- `test_risk_engine.py`: Clean email scoring, critical phishing scoring, positive/mitigating evidence aggregation.
- `test_scenarios.py`: End-to-end multi-layer pipeline execution on Scenarios A, B, C, D, and E.
- `test_security.py`: PII masking, JWT token validation, SSRF URL inspection.

### 2.2 ML Model Training & Benchmark
```bash
python -m app.ml.train
```
- **Corpus**: 29 synthetic academic threat samples across 7 classes.
- **Evaluation**: 100% Weighted Precision, Recall, and F1 Score across Legitimate, Phishing, Executive Impersonation, BEC, Financial Fraud, Malware Delivery, and Spam.
- **Artifacts**: Persisted to `model_store/threat_classifier.pkl` and `model_store/tfidf_vectorizer.pkl`.

### 2.3 End-to-End Pipeline & Graph Integration
```bash
python scratch/test_verification.py
```
- Authentication: JWT Login verified.
- 5 Demonstration Scenarios: Ingested, cryptographically hashed, and scored.
- Correlation Graph: 23 entities, 20 edges, and 3 campaign clusters discovered.
- Audit Log: 8 non-repudiable audit events recorded.

### 2.4 Frontend Production Build
```bash
cd frontend
npm.cmd run build
```
- Compiled with Vite 5.4 and TypeScript 5.4.
- Output: `dist/index.html`, `dist/assets/index-DifIcq4V.css` (35.6 KB), `dist/assets/index-jVdLrWxm.js` (477.2 KB) with **zero compilation errors**.

---

## 3. How to Run the Platform

### Option 1: Local Development Server
1. **Start Backend Server:**
   ```bash
   cd backend
   python -m uvicorn app.main:app --port 8000 --reload
   ```
2. **Start Frontend Dev Server:**
   ```bash
   cd frontend
   npm.cmd run dev
   ```
3. Open browser at `http://localhost:5173`.
4. Log in using `analyst` / `AnalystPass123!` (or select any role from the login screen).
5. Click **"Load Test Scenarios (A–E)"** in the top navigation bar to execute any test case with a single click.

### Option 2: Docker Compose
```bash
docker compose up --build
```
Access the application at `http://localhost`.
