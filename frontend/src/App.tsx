import React, { useState } from 'react';
import { Activity, ShieldAlert } from 'lucide-react';

import { Header } from './components';
import { DashboardView } from './dashboard';
import { BrandsView } from './brands';
import { MonitoringView } from './monitoring';
import { FindingsView } from './findings';
import { DetectionsView } from './detections';
import { InvestigationsView } from './investigations';
import { RecoveryView } from './recovery';
import { ReportsView } from './reports';
import { AgentView } from './agent';
import { IntelligenceView } from './intelligence';
import { useTranslation } from './i18n';

type TabId =
  | 'dashboard'
  | 'copilot'
  | 'brands'
  | 'monitoring'
  | 'detections'
  | 'findings'
  | 'lookalike'
  | 'investigations'
  | 'recovery'
  | 'reports';

const validTabs: TabId[] = [
  'dashboard',
  'copilot',
  'brands',
  'monitoring',
  'detections',
  'findings',
  'lookalike',
  'investigations',
  'recovery',
  'reports',
];

export default function App() {
  const { t, language, setLanguage } = useTranslation();

  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [investigationTarget, setInvestigationTarget] = useState('');

  const navigate = (tab: string): void => {
    if (validTabs.includes(tab as TabId)) {
      setActiveTab(tab as TabId);
    }
  };

  const renderView = (): React.ReactNode => {
    switch (activeTab) {
      case 'brands':
        return <BrandsView t={t} />;

      case 'monitoring':
        return (
          <MonitoringView
            t={t}
            onDeepInspect={(target) => {
              setInvestigationTarget(target);
              setActiveTab('investigations');
            }}
          />
        );

      case 'detections':
        return <DetectionsView t={t} />;

      case 'findings':
        return <FindingsView t={t} />;

      case 'lookalike':
        return (
          <IntelligenceView
            t={t}
            onInvestigate={(target) => {
              setInvestigationTarget(target);
              setActiveTab('investigations');
            }}
          />
        );

      case 'copilot':
        return <AgentView t={t} />;

      case 'investigations':
        return <InvestigationsView t={t} defaultTarget={investigationTarget} />;

      case 'recovery':
        return <RecoveryView t={t} />;

      case 'reports':
        return <ReportsView t={t} />;

      case 'dashboard':
      default:
        return <DashboardView t={t} setActiveTab={navigate} />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <Header
        currentLang={language}
        onLanguageChange={setLanguage}
        activeTab={activeTab}
        setActiveTab={navigate}
        t={t}
      />

      <main className="mx-auto min-h-[calc(100vh-120px)] max-w-[1600px] px-4 py-6 sm:px-6 sm:py-8 lg:px-8">
        <div key={activeTab} className="page-enter">
          {renderView()}
        </div>
      </main>

      <footer className="border-t border-slate-800/80 bg-slate-950/80">
        <div className="mx-auto flex max-w-[1600px] flex-col gap-3 px-4 py-5 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-blue-400" />
            <span>
              <span className="font-semibold text-slate-300">
                Find_out
              </span>
              {' '}· {t('app.tagline')}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-emerald-400" />
            <span>
              {t('app.description')}
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
