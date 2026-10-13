
import React, { useState } from 'react';
import { Activity, ShieldAlert } from 'lucide-react';

import { Header } from './components';
import { DashboardView } from './dashboard';
import { BrandsView } from './brands';
import { MonitoringView } from './monitoring';
import { FindingsView } from './findings';
import { InvestigationsView } from './investigations';
import { RecoveryView } from './recovery';
import { ReportsView } from './reports';
import { useTranslation } from './i18n';

type TabId =
  | 'dashboard'
  | 'brands'
  | 'monitoring'
  | 'findings'
  | 'investigations'
  | 'recovery'
  | 'reports';

const validTabs: TabId[] = [
  'dashboard',
  'brands',
  'monitoring',
  'findings',
  'investigations',
  'recovery',
  'reports',
];

export default function App() {
  const { t, language, setLanguage } = useTranslation();

  const [activeTab, setActiveTab] = useState<TabId>('dashboard');

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
        return <MonitoringView t={t} />;

      case 'findings':
        return <FindingsView />;

      case 'investigations':
        return <InvestigationsView t={t} />;

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
              {' '}· Digital Risk Protection Platform
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-emerald-400" />
            <span>
              Evidence-first analysis · Findings depend on available sources
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
