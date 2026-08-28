import axios from 'axios';
import { EmailSummary, EmailDetail, CaseItem, SystemMetrics } from '../types';

const API_BASE = '/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT token to requests if stored
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const api = {
  // Auth
  login: async (username: string, password: string) => {
    const res = await apiClient.post('/auth/login', { username, password });
    if (res.data.access_token) {
      localStorage.setItem('token', res.data.access_token);
      localStorage.setItem('role', res.data.role);
      localStorage.setItem('username', res.data.username);
    }
    return res.data;
  },
  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    localStorage.removeItem('username');
  },
  getCurrentUser: async () => {
    const res = await apiClient.get('/auth/me');
    return res.data;
  },

  // Emails
  uploadEmail: async (file: File, caseId?: number) => {
    const formData = new FormData();
    formData.append('file', file);
    if (caseId) formData.append('case_id', caseId.toString());
    const res = await apiClient.post<EmailDetail>('/emails/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },
  pasteEmail: async (pasteData: {
    subject?: string;
    from_header?: string;
    to_header?: string;
    reply_to_header?: string;
    raw_headers?: string;
    body_text?: string;
    case_id?: number;
  }) => {
    const res = await apiClient.post<EmailDetail>('/emails/paste', pasteData);
    return res.data;
  },
  listEmails: async (classification?: string, search?: string) => {
    const params: any = {};
    if (classification) params.classification = classification;
    if (search) params.search = search;
    const res = await apiClient.get<EmailSummary[]>('/emails', { params });
    return res.data;
  },
  getEmailDetails: async (emailId: number) => {
    const res = await apiClient.get<EmailDetail>(`/emails/${emailId}`);
    return res.data;
  },
  getEmailReportHtml: async (emailId: number) => {
    const res = await apiClient.get(`/emails/${emailId}/report?format=html`, { responseType: 'text' });
    return res.data;
  },

  // Scenarios
  listScenarios: async () => {
    const res = await apiClient.get('/scenarios/list');
    return res.data;
  },
  loadScenario: async (scenarioId: string) => {
    const res = await apiClient.post<EmailDetail>(`/scenarios/load/${scenarioId}`);
    return res.data;
  },

  // Cases
  listCases: async (status?: string) => {
    const params = status ? { status } : {};
    const res = await apiClient.get<CaseItem[]>('/cases', { params });
    return res.data;
  },
  getCaseDetails: async (caseId: number) => {
    const res = await apiClient.get(`/cases/${caseId}`);
    return res.data;
  },
  createCase: async (caseData: { title: string; description: string; severity: string; email_ids?: number[] }) => {
    const res = await apiClient.post('/cases', caseData);
    return res.data;
  },
  updateCase: async (caseId: number, status: string, severity?: string) => {
    const res = await apiClient.patch(`/cases/${caseId}`, { status, severity });
    return res.data;
  },
  addCaseNote: async (caseId: number, note_text: string, emailId?: number) => {
    const res = await apiClient.post(`/cases/${caseId}/notes`, { note_text, email_id: emailId });
    return res.data;
  },

  // Intelligence & Graph
  getCorrelationGraph: async () => {
    const res = await apiClient.get('/graph/correlation');
    return res.data;
  },
  lookupIndicator: async (type: string, value: string) => {
    const res = await apiClient.get(`/intelligence/indicators/${type}/${encodeURIComponent(value)}`);
    return res.data;
  },

  // Evidence
  getEvidenceDetails: async (evidenceId: number) => {
    const res = await apiClient.get(`/evidence/${evidenceId}`);
    return res.data;
  },
  getEvidenceByEmail: async (emailId: number) => {
    const res = await apiClient.get(`/evidence/by-email/${emailId}`);
    return res.data;
  },
  verifyEvidence: async (evidenceId: number) => {
    const res = await apiClient.post(`/evidence/${evidenceId}/verify`);
    return res.data;
  },

  // Admin & Overview
  getMetrics: async () => {
    const res = await apiClient.get<SystemMetrics>('/admin/metrics');
    return res.data;
  },
  getAuditLogs: async (action?: string) => {
    const params = action ? { action } : {};
    const res = await apiClient.get('/admin/audit-logs', { params });
    return res.data;
  },
  getSettings: async () => {
    const res = await apiClient.get('/admin/settings');
    return res.data;
  },
};
