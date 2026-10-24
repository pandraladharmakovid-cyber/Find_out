import React, { useState } from 'react';
import {
  Activity,
  Bell,
  Bot,
  Building2,
  ChevronDown,
  FileSearch,
  Globe,
  LayoutDashboard,
  ListChecks,
  Menu,
  Radar,
  ScanSearch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Siren,
  X,
} from 'lucide-react';
import type { Language, Translator } from './i18n';

type HeaderProps = {
  currentLang: Language;
  onLanguageChange: (lang: Language) => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  t: Translator;
};

type NavigationItem = {
  id: string;
  label: string;
  icon: React.ElementType;
};

const languages: { id: Language; label: string; short: string }[] = [
  { id: 'en', label: 'English', short: 'EN' },
  { id: 'hi', label: 'हिन्दी', short: 'HI' },
  { id: 'te', label: 'తెలుగు', short: 'TE' },
];

function getNavigation(t: Translator): NavigationItem[] {
  return [
    {
      id: 'dashboard',
      label: t('nav.dashboard'),
      icon: LayoutDashboard,
    },
    {
      id: 'copilot',
      label: t('nav.copilot'),
      icon: Bot,
    },
    {
      id: 'brands',
      label: t('nav.brands'),
      icon: Building2,
    },
    {
      id: 'monitoring',
      label: t('nav.monitoring'),
      icon: Radar,
    },
    {
      id: 'external-watch',
      label: t('nav.externalWatch'),
      icon: Globe,
    },
    {
      id: 'detections',
      label: t('nav.detections'),
      icon: ListChecks,
    },
    {
      id: 'findings',
      label: t('nav.findings'),
      icon: ShieldAlert,
    },
    {
      id: 'lookalike',
      label: t('nav.lookalike'),
      icon: ScanSearch,
    },
    {
      id: 'investigations',
      label: t('nav.investigations'),
      icon: FileSearch,
    },
    {
      id: 'recovery',
      label: t('nav.recovery'),
      icon: ShieldCheck,
    },
    {
      id: 'reports',
      label: t('nav.reports'),
      icon: Siren,
    },
  ];
}

export const Header: React.FC<HeaderProps> = ({
  currentLang,
  onLanguageChange,
  activeTab,
  setActiveTab,
  t,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [languageMenuOpen, setLanguageMenuOpen] = useState(false);

  const navigation = getNavigation(t);
  const selectedLanguage =
    languages.find((language) => language.id === currentLang) ?? languages[0];

  const navigate = (tab: string) => {
    setActiveTab(tab);
    setMobileMenuOpen(false);
  };

  const changeLanguage = (language: Language) => {
    onLanguageChange(language);
    setLanguageMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 border-b border-slate-800/90 bg-slate-950/90 backdrop-blur-xl">
      <div className="mx-auto flex h-[68px] max-w-[1600px] items-center justify-between gap-3 px-4 sm:px-6 lg:px-8">
        <button
          type="button"
          onClick={() => navigate('dashboard')}
          className="group flex min-w-0 items-center gap-3 text-left"
          aria-label="Find_out dashboard"
        >
          <span className="relative flex h-10 w-10 shrink-0 items-center justify-center overflow-hidden rounded-xl border border-blue-400/30 bg-gradient-to-br from-blue-500/20 to-violet-500/20 text-blue-300 shadow-lg shadow-blue-950/30 transition duration-300 group-hover:scale-105">
            <Shield className="h-6 w-6" />
            <span className="absolute bottom-1 right-1 h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          </span>
          <span className="min-w-0">
            <span className="block truncate text-lg font-extrabold tracking-tight text-white sm:text-xl">
              Find<span className="text-blue-400">_</span>out
            </span>
            <span className="hidden text-[10px] font-semibold uppercase tracking-[0.17em] text-slate-500 sm:block">
              {t('app.tagline')}
            </span>
          </span>
        </button>

        <nav
          aria-label="Main navigation"
          className="hidden min-w-0 flex-1 items-center justify-center gap-1 xl:flex"
        >
          {navigation.map((item) => {
            const active = activeTab === item.id;
            const Icon = item.icon;

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => navigate(item.id)}
                aria-current={active ? 'page' : undefined}
                className={`relative inline-flex items-center gap-2 whitespace-nowrap rounded-lg px-3 py-2.5 text-xs font-medium transition duration-200 ${
                  active
                    ? 'bg-blue-500/10 text-blue-300'
                    : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {item.label}
                {active && (
                  <span className="absolute inset-x-3 -bottom-[1px] h-0.5 rounded-full bg-blue-400" />
                )}
              </button>
            );
          })}
        </nav>

        <div className="flex shrink-0 items-center gap-2">
          <div className="relative">
            <button
              type="button"
              onClick={() => setLanguageMenuOpen((open) => !open)}
              aria-expanded={languageMenuOpen}
              aria-haspopup="menu"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2.5 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white"
            >
              <Globe className="h-4 w-4 text-blue-300" />
              <span>{selectedLanguage.short}</span>
              <ChevronDown
                className={`h-3.5 w-3.5 transition-transform ${
                  languageMenuOpen ? 'rotate-180' : ''
                }`}
              />
            </button>

            {languageMenuOpen && (
              <>
                <button
                  type="button"
                  aria-label="Close language menu"
                  className="fixed inset-0 z-40 cursor-default"
                  onClick={() => setLanguageMenuOpen(false)}
                />
                <div
                  role="menu"
                  aria-label="Select language"
                  className="absolute right-0 top-full z-50 mt-2 w-40 overflow-hidden rounded-xl border border-slate-800 bg-slate-950 p-1.5 shadow-2xl shadow-black/40"
                >
                  {languages.map((language) => (
                    <button
                      key={language.id}
                      type="button"
                      role="menuitem"
                      onClick={() => changeLanguage(language.id)}
                      className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-sm transition ${
                        currentLang === language.id
                          ? 'bg-blue-500/10 text-blue-300'
                          : 'text-slate-300 hover:bg-slate-900'
                      }`}
                    >
                      <span>{language.label}</span>
                      {currentLang === language.id && (
                        <Activity className="h-3.5 w-3.5" />
                      )}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>

          <button
            type="button"
            onClick={() => navigate('reports')}
            aria-label="Open reports and alerts"
            title="Reports and alerts"
            className={`relative hidden rounded-lg border p-2.5 transition sm:inline-flex ${
              activeTab === 'reports'
                ? 'border-blue-500/30 bg-blue-500/10 text-blue-300'
                : 'border-slate-800 bg-slate-900/70 text-slate-400 hover:text-white'
            }`}
          >
            <Bell className="h-4 w-4" />
          </button>

          <button
            type="button"
            onClick={() => setMobileMenuOpen((open) => !open)}
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={mobileMenuOpen}
            className="inline-flex rounded-lg border border-slate-800 bg-slate-900/70 p-2.5 text-slate-300 transition hover:bg-slate-800 xl:hidden"
          >
            {mobileMenuOpen ? (
              <X className="h-5 w-5" />
            ) : (
              <Menu className="h-5 w-5" />
            )}
          </button>
        </div>
      </div>

      <div className="border-t border-slate-800/70 bg-slate-950/80 px-4 py-2 xl:hidden">
        <div className="mx-auto flex max-w-[1600px] items-center gap-2 overflow-x-auto">
          {navigation.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => navigate(item.id)}
                aria-current={active ? 'page' : undefined}
                className={`inline-flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-medium transition ${
                  active
                    ? 'border border-blue-500/20 bg-blue-500/10 text-blue-300'
                    : 'border border-transparent text-slate-400 hover:bg-slate-900 hover:text-white'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {item.label}
              </button>
            );
          })}
        </div>
      </div>

      {mobileMenuOpen && (
        <div className="border-t border-slate-800 bg-slate-950 px-4 py-3 shadow-xl xl:hidden">
          <nav aria-label="Mobile navigation menu" className="mx-auto grid max-w-[1600px] grid-cols-2 gap-2 sm:grid-cols-3">
            {navigation.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigate(item.id)}
                  aria-current={active ? 'page' : undefined}
                  className={`flex min-h-12 items-center gap-2 rounded-xl border px-3 py-3 text-left text-sm transition ${
                    active
                      ? 'border-blue-500/30 bg-blue-500/10 text-blue-300'
                      : 'border-slate-800 bg-slate-900/50 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
          <p className="mx-auto mt-3 flex max-w-[1600px] items-center gap-2 text-[11px] text-slate-600">
            <Activity className="h-3.5 w-3.5" />
            Find_out · Digital Risk Protection Platform
          </p>
        </div>
      )}
    </header>
  );
};

export default Header;
