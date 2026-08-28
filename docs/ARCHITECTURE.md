# System Architecture & Data-Flow Specification

## 1. System Architecture Overview

The **AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform** is constructed as a high-throughput, modular cybersecurity monolith. It provides end-to-end evidence preservation, RFC 5322 header reconstruction, multi-vector authentication analysis, NLP social engineering detection, static payload inspection, infrastructure geolocation, explainable 7-tier risk scoring, and entity correlation.

```mermaid
graph TD
    User([Security Analyst / Investigator / Admin / Auditor]) -->|HTTPS / REST API| Frontend[React + TypeScript Dashboard]
    Frontend -->|JWT Auth / Reverse Proxy| API[FastAPI Backend Gateway]

    subgraph Core Ingestion & Preservation
        API --> IngestionService[Ingestion & Evidence Service]
        IngestionService --> Storage[Immutable Evidence Storage (.eml / SHA-256)]
        IngestionService --> Custody[Chain of Custody Logger]
    end

    subgraph Forensic Inspection Engine
        API --> Parser[RFC 5322 Header & Relay Hop Parser]
        Parser --> IPClassifier[IP Bogon & Public Classifier]
        Parser --> EarliestIP[Earliest Public IP Resolver]
        
        API --> AuthEngine[SPF, DKIM, DMARC & ARC Engine]
        AuthEngine --> LookalikeDetector[Lookalike Authentication Trap Resolver]
        
        API --> DomainEngine[Levenshtein, Jaro-Winkler & Homoglyph Engine]
        API --> ContentNLP[Content NLP & Social Engineering Heuristics]
        API --> URLAnalyzer[URL Deceptive Anchor & Entropy Inspector]
        API --> AttachmentAnalyzer[Static Magic Byte & Macro Inspector]
    end

    subgraph Intelligence & Scoring
        EarliestIP --> GeoEnrichment[Geolocation & ASN Enrichment Service]
        Parser --> ThreatIntel[Threat Intel Feeds: AbuseIPDB, VirusTotal, URLhaus]
        ContentNLP --> MLEngine[Calibrated ML Model: TF-IDF + Logistic Regression]
        
        ForensicResults[Multi-Layer Forensic Signals] --> RiskEngine[7-Tier Explainable Risk Engine 0-100]
    end

    subgraph Correlation & Storage
        RiskEngine --> DB[(Relational DB: PostgreSQL / SQLite)]
        RiskEngine --> GraphEngine[NetworkX Entity Correlation Engine]
        GraphEngine --> GraphDB[Campaign Clusters & Centrality Repo]
        RiskEngine --> ReportEngine[Forensic HTML / PDF Report Generator]
    end
```

---

## 2. End-to-End Forensic Data-Flow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant UI as React Frontend
    participant API as FastAPI Ingestion
    participant Store as Evidence FileStore
    participant Pipe as Master Forensic Pipeline
    participant ML as ML NLP Engine
    participant Graph as Correlation Engine
    participant DB as Relational Database

    Analyst->>UI: Upload raw .eml file or test scenario
    UI->>API: POST /api/v1/emails/upload (Multipart)
    API->>Store: Calculate SHA-256 & persist immutable byte copy
    API->>DB: Log Initial Chain-of-Custody Acquisition Event
    API->>Pipe: Execute Multi-Layer Inspection
    Pipe->>Pipe: Extract RFC 5322 Headers & Reconstruct Relay Hops
    Pipe->>Pipe: Identify Earliest Reliable Public Relay IP & Geolocation
    Pipe->>Pipe: Evaluate SPF, DKIM, DMARC Alignment & Traps
    Pipe->>Pipe: Inspect URLs, Deceptive Anchors & Attachments
    Pipe->>ML: Predict Threat Category & Extract Contributing Tokens
    Pipe->>Pipe: Compute 7-Tier Explainable Risk Score (0-100)
    Pipe->>Graph: Map Nodes & Edges (Emails, Senders, Domains, IPs, Hashes)
    Pipe->>DB: Persist 22+ Relational Entities & Alerts
    API-->>UI: Return Full Forensic Assessment & Indicators
    UI-->>Analyst: Render Risk Gauge, Timeline, Map & Explainability Breakdown
```

---

## 3. Use-Case Diagram

```mermaid
graph LR
    subgraph Actors
        A[Analyst]
        AD[Administrator]
        INV[Investigator]
        AUD[Auditor]
    end

    subgraph Platform Capabilities
        UC1(Ingest .EML & Paste Headers)
        UC2(Inspect Relay Hop Timeline)
        UC3(Validate SPF/DKIM/DMARC)
        UC4(View Geolocation Map)
        UC5(Explore Campaign Graph)
        UC6(Manage Investigation Cases)
        UC7(Export Forensic Reports)
        UC8(Audit Cryptographic Hashes)
        UC9(Configure Risk Weights & Policies)
        UC10(Toggle Privacy PII Masking)
    end

    A --> UC1
    A --> UC2
    A --> UC3
    A --> UC4
    A --> UC6
    A --> UC7
    A --> UC10

    INV --> UC5
    INV --> UC6
    INV --> UC7
    INV --> UC8

    AD --> UC9
    AD --> UC10

    AUD --> UC8
```
