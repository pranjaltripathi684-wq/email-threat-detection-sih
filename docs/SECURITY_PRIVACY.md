# Security Controls & Privacy Architecture

## 1. Security Architecture Controls

### 1.1 Safe Parsing & Execution Isolation
- **Zero Attachment Execution**: The platform operates in a strictly static inspection mode. Binary payloads (`.exe`, `.dll`, `.vbs`, `.ps1`) and macro-enabled documents (`.docm`, `.xlsm`) are inspected using binary magic-byte offsets, structural file headers, and cryptographic hashing (SHA-256 / MD5). No dynamic execution occurs on the server host.
- **HTML & Script Sanitization**: Email HTML content is parsed using BeautifulSoup. Embedded `<script>`, `<iframe>`, and interactive form elements are disarmed and converted into structured forensic risk indicators.
- **SSRF (Server-Side Request Forgery) Protection**: Extracted URLs from emails are inspected using syntactic domain parsing, heuristic entropy calculation, and IP-bogon classification. The platform does not follow or issue automated HTTP GET requests to arbitrary third-party endpoints without operator authorization.

### 1.2 Cryptographic Evidence Integrity & Chain of Custody
- **Immutable Storage**: Upon ingestion, raw RFC 5322 byte streams are hashed with SHA-256 and written to dedicated read-only storage.
- **Audit-Stamped Ledger**: Any access, duplicate verification, or report export appends an immutable event to `custody_events` recording timestamp (UTC), actor identity, actor role, pre-action hash, and post-action hash.

### 1.3 Role-Based Access Control (RBAC)
- **Role Separation**:
  - `Analyst`: Ingestion, indicator inspection, case updates, report exports.
  - `Administrator`: Threshold configuration, user administration, policy overrides.
  - `Investigator`: Campaign correlation, evidence reviews, formal report sign-off.
  - `Auditor`: Immutable audit trail inspection and hash verification without edit permissions.
- **JWT Cryptography**: Signed using HMAC-SHA256 with strict expiration timeouts and refresh token rotation.

---

## 2. Privacy Preservation & PII Protection

### 2.1 Field-Level PII Masking
- **Default Privacy Mode**: Ordinary analyst views mask recipient email addresses (e.g. `j***e@enterprise.com`) to protect employee identities in accordance with data minimization standards.
- **Analyst Toggle**: Authorized roles can toggle masking mode when full headers are required for formal incident containment.

### 2.2 Local-First / Zero-Leak Intelligence Architecture
- **Offline Mock Repositories**: The platform contains high-fidelity offline threat intelligence and geolocation databases. Demonstrations and training runs operate completely offline without transmitting internal corporate email indicators to external cloud APIs.
