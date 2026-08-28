import React, { useState, useEffect } from 'react';
import { api } from './services/api';
import { EmailDetail } from './types';
import { Navbar } from './components/Navbar';
import { Sidebar, ActiveTab } from './components/Sidebar';
import { ScenarioPickerModal } from './components/ScenarioPickerModal';

// Pages
import { DashboardOverview } from './pages/DashboardOverview';
import { EmailUploadPage } from './pages/EmailUploadPage';
import { AnalysisResultPage } from './pages/AnalysisResultPage';
import { HeaderRelayPage } from './pages/HeaderRelayPage';
import { AuthenticationPage } from './pages/AuthenticationPage';
import { UrlAttachmentPage } from './pages/UrlAttachmentPage';
import { GeolocationMapPage } from './pages/GeolocationMapPage';
import { CampaignGraphPage } from './pages/CampaignGraphPage';
import { CaseManagementPage } from './pages/CaseManagementPage';
import { EvidenceCustodyPage } from './pages/EvidenceCustodyPage';
import { ForensicReportPage } from './pages/ForensicReportPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { UserManagementPage } from './pages/UserManagementPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { SettingsPage } from './pages/SettingsPage';
import { LoginPage } from './pages/LoginPage';

export const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => !!localStorage.getItem('token'));
  const [currentUser, setCurrentUser] = useState<{ username: string; role: string }>({
    username: localStorage.getItem('username') || 'analyst',
    role: localStorage.getItem('role') || 'Analyst',
  });

  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [selectedEmail, setSelectedEmail] = useState<EmailDetail | null>(null);
  const [selectedEmailId, setSelectedEmailId] = useState<number | null>(null);
  const [maskPII, setMaskPII] = useState<boolean>(true);
  const [showScenarioModal, setShowScenarioModal] = useState<boolean>(false);
  const [isLoadingScenario, setIsLoadingScenario] = useState<boolean>(false);

  // Email selection handler
  const handleSelectEmail = async (emailId: number) => {
    setSelectedEmailId(emailId);
    try {
      const details = await api.getEmailDetails(emailId);
      setSelectedEmail(details);
      setActiveTab('analysis');
    } catch (e) {
      console.error('Failed to fetch email details:', e);
    }
  };

  // Scenario loading handler
  const handleSelectScenario = async (scenarioId: string) => {
    setIsLoadingScenario(true);
    try {
      const emailDetail = await api.loadScenario(scenarioId);
      setSelectedEmail(emailDetail);
      setSelectedEmailId(emailDetail.id);
      setShowScenarioModal(false);
      setActiveTab('analysis');
    } catch (e) {
      console.error('Failed to load scenario:', e);
    } finally {
      setIsLoadingScenario(false);
    }
  };

  // PII masking helper
  const maskEmailAddress = (emailStr?: string): string => {
    if (!maskPII || !emailStr || !emailStr.includes('@')) return emailStr || '';
    try {
      const parts = emailStr.split('@');
      const local = parts[0];
      const domain = parts[1];
      if (local.length <= 2) return `${local[0]}***@${domain}`;
      return `${local[0]}***${local[local.length - 1]}@${domain}`;
    } catch {
      return emailStr;
    }
  };

  const handleLogout = () => {
    api.logout();
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return (
      <LoginPage
        onLoginSuccess={(user) => {
          setCurrentUser(user);
          setIsAuthenticated(true);
        }}
      />
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-[#080d1a] text-slate-100">
      <Navbar
        maskPII={maskPII}
        setMaskPII={setMaskPII}
        currentUser={currentUser}
        onLogout={handleLogout}
        onOpenScenarios={() => setShowScenarioModal(true)}
      />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          selectedEmailId={selectedEmailId}
        />

        <main className="flex-1 p-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
          {activeTab === 'overview' && (
            <DashboardOverview
              onSelectEmail={handleSelectEmail}
              maskEmail={maskEmailAddress}
            />
          )}

          {activeTab === 'upload' && (
            <EmailUploadPage
              onAnalysisComplete={(detail) => {
                setSelectedEmail(detail);
                setSelectedEmailId(detail.id);
                setActiveTab('analysis');
              }}
              onOpenScenarios={() => setShowScenarioModal(true)}
            />
          )}

          {activeTab === 'analysis' && (
            <AnalysisResultPage
              email={selectedEmail}
              onNavigateTab={setActiveTab}
              maskEmail={maskEmailAddress}
            />
          )}

          {activeTab === 'relay' && <HeaderRelayPage email={selectedEmail} />}

          {activeTab === 'auth' && <AuthenticationPage email={selectedEmail} />}

          {activeTab === 'urls_attachments' && <UrlAttachmentPage email={selectedEmail} />}

          {activeTab === 'geomap' && <GeolocationMapPage email={selectedEmail} />}

          {activeTab === 'graph' && <CampaignGraphPage />}

          {activeTab === 'cases' && <CaseManagementPage selectedEmailId={selectedEmailId} />}

          {activeTab === 'evidence' && <EvidenceCustodyPage selectedEmailId={selectedEmailId} />}

          {activeTab === 'report' && <ForensicReportPage selectedEmailId={selectedEmailId} />}

          {activeTab === 'intel' && <ThreatIntelligencePage />}

          {activeTab === 'users' && <UserManagementPage />}

          {activeTab === 'audit' && <AuditLogsPage />}

          {activeTab === 'settings' && <SettingsPage />}
        </main>
      </div>

      <ScenarioPickerModal
        isOpen={showScenarioModal}
        onClose={() => setShowScenarioModal(false)}
        onSelectScenario={handleSelectScenario}
        isLoading={isLoadingScenario}
      />
    </div>
  );
};
