export interface Hop {
  id: number;
  hop_order: number;
  receiving_server?: string;
  sending_server?: string;
  extracted_ip?: string;
  ip_classification: string;
  timestamp_raw?: string;
  timestamp_utc?: string;
  time_delta_seconds?: number;
  tls_status: boolean;
  tls_cipher?: string;
  is_earliest_reliable_public_ip: boolean;
  anomaly_flags?: string;
  geo_country?: string;
  geo_city?: string;
  geo_lat?: number;
  geo_lon?: number;
  asn_org?: string;
}

export interface AuthResult {
  spf_result: string;
  spf_domain?: string;
  dkim_present: boolean;
  dkim_result: string;
  dkim_domain?: string;
  dkim_selector?: string;
  dmarc_result: string;
  dmarc_policy: string;
  dmarc_alignment: string;
  arc_present: boolean;
  arc_result: string;
  from_reply_to_aligned: boolean;
  is_lookalike_domain_auth: boolean;
  natural_language_explanation?: string;
}

export interface EmailUrlItem {
  id: number;
  raw_url: string;
  display_text?: string;
  domain?: string;
  is_ip_based: boolean;
  is_punycode: boolean;
  is_shortened: boolean;
  is_deceptive: boolean;
  has_suspicious_port: boolean;
  risk_score: number;
  risk_reasons: string[];
}

export interface EmailAttachmentItem {
  id: number;
  filename: string;
  file_extension?: string;
  declared_mime_type?: string;
  magic_file_type?: string;
  file_size: number;
  sha256_hash: string;
  has_double_extension: boolean;
  has_macros: boolean;
  is_script_or_executable: boolean;
  is_password_protected: boolean;
  risk_score: number;
  risk_reasons: string[];
}

export interface EmailDetail {
  id: number;
  original_filename: string;
  sha256_hash: string;
  file_size: number;
  upload_time: string;
  raw_subject?: string;
  raw_from?: string;
  raw_to?: string;
  raw_cc?: string;
  raw_reply_to?: string;
  raw_return_path?: string;
  raw_date?: string;
  message_id?: string;
  sender_domain?: string;
  reply_to_domain?: string;
  sanitized_body_text?: string;
  sanitized_body_html?: string;
  earliest_public_ip?: string;
  earliest_public_ip_country?: string;
  earliest_public_ip_city?: string;
  earliest_public_ip_org?: string;
  total_risk_score: number;
  risk_classification: string;
  confidence_score: number;
  score_breakdown?: {
    headers?: { score: number; max: number };
    authentication?: { score: number; max: number };
    sender_domain?: { score: number; max: number };
    content_nlp?: { score: number; max: number };
    urls?: { score: number; max: number };
    attachments?: { score: number; max: number };
    threat_intel?: { score: number; max: number };
  };
  positive_evidence?: string[];
  negative_evidence?: string[];
  missing_evidence?: string[];
  recommended_action?: string;
  hops: Hop[];
  auth_results?: AuthResult;
  urls: EmailUrlItem[];
  attachments: EmailAttachmentItem[];
}

export interface EmailSummary {
  id: number;
  original_filename: string;
  sha256_hash: string;
  upload_time: string;
  raw_subject?: string;
  raw_from?: string;
  raw_to?: string;
  sender_domain?: string;
  total_risk_score: number;
  risk_classification: string;
  confidence_score: number;
  earliest_public_ip?: string;
  earliest_public_ip_country?: string;
  case_id?: number;
}

export interface CaseItem {
  id: number;
  case_number: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  assigned_analyst_id?: number;
  created_at: string;
  updated_at: string;
  email_count: number;
}

export interface SystemMetrics {
  total_analyzed_emails: number;
  critical_count: number;
  high_risk_count: number;
  suspicious_count: number;
  low_risk_count: number;
  open_cases_count: number;
  active_alerts_count: number;
  recent_alerts: Array<{
    id: number;
    title: string;
    severity: string;
    category: string;
    created_at: string;
  }>;
  average_analysis_time_ms: number;
}
