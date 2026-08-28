# REST API Specification (v1)

## Base URL
`/api/v1`

All protected endpoints require the HTTP Authorization Header:
`Authorization: Bearer <JWT_ACCESS_TOKEN>`

---

## 1. Authentication Endpoints

### `POST /auth/register`
- **Description:** Registers a new operator account with assigned RBAC role.
- **Request Body:**
  ```json
  {
    "username": "analyst_john",
    "email": "john@enterprise.com",
    "password": "SecurePassword123!",
    "full_name": "John Doe",
    "role": "Analyst"
  }
  ```
- **Response:** `200 OK` (UserResponse schema).

### `POST /auth/login`
- **Description:** Authenticates credentials and returns signed JWT access and refresh tokens.
- **Request Body:**
  ```json
  {
    "username": "analyst",
    "password": "AnalystPass123!"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "role": "Analyst",
    "username": "analyst"
  }
  ```

---

## 2. Email Ingestion & Forensics Endpoints

### `POST /emails/upload`
- **Description:** Safely ingests RFC 5322 `.eml` file, computes SHA-256 evidence hash, records custody event, and runs multi-layer pipeline.
- **Content-Type:** `multipart/form-data`
- **Parameters:** `file` (File), `case_id` (Optional integer).
- **Response:** `200 OK` (EmailDetailResponse schema).

### `POST /emails/paste`
- **Description:** Ingests email from raw headers and text/HTML body.
- **Request Body:**
  ```json
  {
    "subject": "Urgent: Account Verification",
    "from_header": "PayPal Support <security@paypa1-update.com>",
    "raw_headers": "Received: from ...",
    "body_text": "Please confirm password...",
    "case_id": null
  }
  ```
- **Response:** `200 OK` (EmailDetailResponse).

### `GET /emails`
- **Description:** Lists analyzed emails with filtering and pagination.
- **Query Params:** `skip` (int), `limit` (int), `classification` (str), `search` (str).
- **Response:** `200 OK` (`Array<EmailSummaryResponse>`).

### `GET /emails/{id}`
- **Description:** Returns detailed forensic breakdown for a single email (hops, auth matrix, extracted URLs, attachment metadata, score breakdown, positive/negative evidence).
- **Response:** `200 OK` (EmailDetailResponse).

### `GET /emails/{id}/report`
- **Description:** Generates printable formal forensic intelligence report.
- **Query Params:** `format` (`html` or `json`).
- **Response:** `200 OK` (HTML Document or JSON object).

---

## 3. Demonstration Scenarios

### `GET /scenarios/list`
- **Description:** Returns available pre-packaged synthetic academic demonstration scenarios (A through E).

### `POST /scenarios/load/{scenario_id}`
- **Description:** Ingests and executes forensic pipeline on Scenario `A`, `B`, `C`, `D`, or `E`.

---

## 4. Cases & Threat Intelligence

### `POST /cases`
- **Description:** Creates a new incident case and attaches specified email IDs.
- **Request Body:**
  ```json
  {
    "title": "Executive Impersonation BEC Campaign",
    "description": "Targeting accounting department with fraudulent bank routing updates",
    "severity": "High",
    "email_ids": [1, 2]
  }
  ```

### `GET /intelligence/indicators/{type}/{value}`
- **Description:** Queries threat intelligence feeds and reputation for an IP, domain, URL, or hash.

### `GET /graph/correlation`
- **Description:** Returns full network graph (nodes, edges, connected component campaign clusters, centrality metrics) for Cytoscape / Canvas rendering.

### `POST /evidence/{id}/verify`
- **Description:** Recalculates cryptographic SHA-256 hash against disk storage and records an audited custody event.
