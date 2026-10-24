import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  CircleSlash,
  Loader2,
  Send,
  Sparkles,
  User,
  XCircle,
} from 'lucide-react';

import { apiRequest, ApiError } from './api';
import type { Translator } from './i18n';

/**
 * Find_out Copilot — the dashboard chat box.
 *
 * Sits at the top of the dashboard, answers from live platform data through
 * POST /api/agent/chat, keeps the conversation for follow-up questions, and
 * shows the module-health chips so an analyst can see *why* an answer says a
 * source is unavailable. If the model gateway is down the backend answers
 * deterministically and the widget says so instead of pretending.
 */

type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  keyPoints?: string[];
  suggestedActions?: string[];
  engine?: 'llm' | 'deterministic';
  model?: string | null;
  notice?: string | null;
  latencyMs?: number;
  error?: boolean;
};

type ModuleChip = {
  id: string;
  name: string;
  status: 'ok' | 'degraded' | 'not_configured' | 'error';
  detail: string;
};

type AgentChatProps = {
  t: Translator;
  onNavigate?: (tab: string) => void;
};

/** Suggested actions that map onto a real screen become navigation buttons. */
const TAB_FOR_ACTION: Array<{ match: RegExp; tab: string }> = [
  { match: /finding|triage|evidence/i, tab: 'findings' },
  { match: /brand|registry|asset/i, tab: 'brands' },
  { match: /investigat/i, tab: 'investigations' },
  { match: /recovery|incident|restore/i, tab: 'recovery' },
  { match: /report|takedown|complaint/i, tab: 'reports' },
  { match: /monitor|scan/i, tab: 'monitoring' },
];

const SUGGESTIONS = [
  'What is the current risk posture?',
  'Which modules are broken right now?',
  'What should I triage first?',
];

function statusStyles(status: ModuleChip['status']): string {
  switch (status) {
    case 'ok':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
    case 'degraded':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
    case 'not_configured':
      return 'border-slate-600 bg-slate-800/60 text-slate-300';
    default:
      return 'border-rose-500/30 bg-rose-500/10 text-rose-300';
  }
}

function statusLabel(status: ModuleChip['status'], detail = ''): string {
  switch (status) {
    case 'ok':
      return 'working';
    case 'degraded':
      // "degraded" here usually means "configured, not probed yet" — say that
      // instead of implying the module is broken.
      return /run a deep check/i.test(detail) ? 'needs check' : 'degraded';
    case 'not_configured':
      return 'no key';
    default:
      return 'error';
  }
}

export const AgentChat: React.FC<AgentChatProps> = ({ t, onNavigate }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [modules, setModules] = useState<ModuleChip[]>([]);
  const [showModules, setShowModules] = useState(false);
  const [gateway, setGateway] = useState<{
    configured: boolean;
    model: string;
    lastEngine?: 'llm' | 'deterministic';
  }>({ configured: false, model: '' });
  const scrollRef = useRef<HTMLDivElement | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const status = await apiRequest<any>('/agent/status');
      const provider = status?.data?.agent?.provider;
      setGateway({
        configured: Boolean(provider?.configured),
        model: String(provider?.model ?? provider?.primaryModel ?? ''),
      });
    } catch {
      setGateway({ configured: false, model: '' });
    }

    try {
      const diagnostics = await apiRequest<any>('/agent/diagnostics?deep=0');
      const rows: ModuleChip[] = (diagnostics?.data?.modules ?? []).map((module: any) => ({
        id: String(module.id ?? module.name),
        name: String(module.name ?? module.id),
        status: (module.status ?? 'degraded') as ModuleChip['status'],
        detail: String(module.detail ?? ''),
      }));
      setModules(rows);
    } catch {
      setModules([]);
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, sending]);

  const send = useCallback(
    async (raw: string) => {
      const question = raw.trim();
      if (!question || sending) return;

      const history = messages
        .filter((message) => !message.error)
        .slice(-6)
        .map((message) => ({ role: message.role, content: message.content }));

      const userMessage: ChatMessage = {
        id: `u-${Date.now()}`,
        role: 'user',
        content: question,
      };

      setMessages((current) => [...current, userMessage]);
      setInput('');
      setSending(true);

      try {
        const response = await apiRequest<any>('/agent/chat', {
          method: 'POST',
          body: JSON.stringify({ message: question, history }),
          timeoutMs: 65000,
        });

        const data = response?.data ?? response;
        setMessages((current) => [
          ...current,
          {
            id: `a-${Date.now()}`,
            role: 'assistant',
            content: String(data?.answer ?? 'The assistant returned an empty answer.'),
            keyPoints: Array.isArray(data?.keyPoints) ? data.keyPoints : [],
            suggestedActions: Array.isArray(data?.suggestedActions)
              ? data.suggestedActions
              : [],
            engine: data?.engine === 'llm' ? 'llm' : 'deterministic',
            model: data?.model ?? null,
            notice: data?.notice ?? null,
            latencyMs: Number(data?.latencyMs ?? 0),
          },
        ]);
        setGateway((current) => ({
          ...current,
          lastEngine: data?.engine === 'llm' ? 'llm' : 'deterministic',
        }));
      } catch (error) {
        const message =
          error instanceof ApiError
            ? error.message
            : 'The assistant could not be reached. Check that the backend is running.';
        setMessages((current) => [
          ...current,
          {
            id: `e-${Date.now()}`,
            role: 'assistant',
            content: message,
            error: true,
          },
        ]);
      } finally {
        setSending(false);
      }
    },
    [messages, sending],
  );

  const failing = modules.filter((module) => module.status !== 'ok');
  const engineLabel = messages.length
    ? messages[messages.length - 1]?.engine === 'llm'
      ? `${messages[messages.length - 1]?.model ?? gateway.model}`
      : 'rule-based answer'
    : gateway.configured
      ? gateway.model || 'AI gateway ready'
      : 'AI gateway not configured';

  return (
    <section className="surface-card overflow-hidden">
      <header className="flex flex-col gap-3 border-b border-slate-800 bg-gradient-to-r from-blue-500/10 via-slate-900/60 to-violet-500/10 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-blue-500/30 bg-blue-500/15 p-2 text-blue-300">
            <Bot className="h-5 w-5" />
          </div>
          <div>
            <h2 className="flex items-center gap-2 text-base font-semibold text-white">
              {t('chat.title')}
              <span className="rounded-full border border-blue-400/30 bg-blue-400/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-blue-200">
                AI Agent
              </span>
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">{t('chat.subtitle')}</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${
              gateway.configured
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
            }`}
            title={gateway.configured ? 'OPENAI_BASE_URL + OPENAI_API_KEY are set' : 'AI gateway env vars are empty'}
          >
            <Sparkles className="h-3 w-3" />
            {engineLabel}
          </span>

          <button
            type="button"
            onClick={() => setShowModules((value) => !value)}
            className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-900/70 px-2.5 py-1 text-[11px] font-medium text-slate-300 hover:border-slate-600"
          >
            {failing.length > 0 ? (
              <AlertTriangle className="h-3 w-3 text-amber-400" />
            ) : (
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
            )}
            {t('chat.moduleHealth')}: {modules.length - failing.length}/{modules.length}
            {showModules ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
        </div>
      </header>

      {showModules && (
        <div className="flex flex-wrap gap-2 border-b border-slate-800 bg-slate-950/60 px-5 py-3">
          {modules.length === 0 ? (
            <span className="text-xs text-slate-500">
              Module health is unavailable until the diagnostics endpoint responds.
            </span>
          ) : (
            modules.map((module) => (
              <span
                key={module.id}
                title={module.detail}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[11px] ${statusStyles(module.status)}`}
              >
                {module.status === 'ok' ? (
                  <CheckCircle2 className="h-3 w-3" />
                ) : module.status === 'error' ? (
                  <XCircle className="h-3 w-3" />
                ) : (
                  <CircleSlash className="h-3 w-3" />
                )}
                {module.name}
                <span className="opacity-60">· {statusLabel(module.status, module.detail)}</span>
              </span>
            ))
          )}
        </div>
      )}

      <div
        ref={scrollRef}
        className="max-h-[320px] min-h-[132px] space-y-3 overflow-y-auto px-5 py-4"
      >
        {messages.length === 0 && !sending ? (
          <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/40 p-4">
            <p className="text-sm text-slate-300">{t('chat.empty')}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {SUGGESTIONS.map((suggestion) => (
                <button
                  key={suggestion}
                  type="button"
                  onClick={() => void send(suggestion)}
                  className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-xs text-slate-300 transition hover:border-blue-500/40 hover:text-blue-200"
                >
                  {suggestion}
                  <ArrowRight className="h-3 w-3" />
                </button>
              ))}
            </div>
          </div>
        ) : null}

        {messages.map((message) => (
          <div
            key={message.id}
            className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : ''}`}
          >
            {message.role === 'assistant' && (
              <div
                className={`mt-0.5 h-7 w-7 shrink-0 rounded-lg border p-1.5 ${
                  message.error
                    ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                    : 'border-blue-500/30 bg-blue-500/10 text-blue-300'
                }`}
              >
                <Bot className="h-4 w-4" />
              </div>
            )}

            <div
              className={`max-w-[85%] rounded-xl border px-3.5 py-2.5 text-sm leading-6 ${
                message.role === 'user'
                  ? 'border-blue-500/30 bg-blue-500/10 text-blue-50'
                  : message.error
                    ? 'border-rose-500/30 bg-rose-500/10 text-rose-100'
                    : 'border-slate-800 bg-slate-950/60 text-slate-200'
              }`}
            >
              <p className="whitespace-pre-wrap">{message.content}</p>

              {message.keyPoints && message.keyPoints.length > 0 && (
                <ul className="mt-2 space-y-1 border-t border-slate-800 pt-2 text-xs text-slate-400">
                  {message.keyPoints.map((point, index) => (
                    <li key={index} className="flex gap-2">
                      <span className="text-blue-400">•</span>
                      <span>{point}</span>
                    </li>
                  ))}
                </ul>
              )}

              {message.suggestedActions && message.suggestedActions.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {message.suggestedActions.map((action, index) => {
                    const tab = TAB_FOR_ACTION.find((entry) => entry.match.test(action))?.tab;
                    return (
                      <button
                        key={index}
                        type="button"
                        onClick={() => (tab && onNavigate ? onNavigate(tab) : void send(action))}
                        className="rounded-full border border-slate-700 bg-slate-900/70 px-2 py-0.5 text-left text-[11px] text-slate-300 transition hover:border-blue-500/40 hover:text-blue-200"
                      >
                        {action}
                      </button>
                    );
                  })}
                </div>
              )}

              {message.notice && (
                <p className="mt-2 flex items-start gap-1.5 rounded-lg border border-amber-500/20 bg-amber-500/5 px-2 py-1.5 text-[11px] text-amber-200/80">
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                  {message.notice}
                </p>
              )}

              {message.role === 'assistant' && !message.error && (
                <p className="mt-2 text-[10px] uppercase tracking-wider text-slate-500">
                  {message.engine === 'llm' ? message.model ?? 'model' : 'rule-based answer'}
                  {message.latencyMs ? ` · ${(message.latencyMs / 1000).toFixed(1)}s` : ''}
                </p>
              )}
            </div>

            {message.role === 'user' && (
              <div className="mt-0.5 h-7 w-7 shrink-0 rounded-lg border border-slate-700 bg-slate-800 p-1.5 text-slate-300">
                <User className="h-4 w-4" />
              </div>
            )}
          </div>
        ))}

        {sending && (
          <div className="flex items-center gap-3 text-xs text-slate-400">
            <div className="h-7 w-7 rounded-lg border border-blue-500/30 bg-blue-500/10 p-1.5 text-blue-300">
              <Loader2 className="h-4 w-4 animate-spin" />
            </div>
            {t('chat.thinking')}
          </div>
        )}
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          void send(input);
        }}
        className="flex items-center gap-2 border-t border-slate-800 bg-slate-950/60 px-4 py-3"
      >
        <input
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder={t('chat.placeholder')}
          aria-label={t('chat.placeholder')}
          className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500/60 focus:outline-none"
          disabled={sending}
        />
        <button
          type="submit"
          disabled={sending || !input.trim()}
          className="btn-primary inline-flex items-center gap-2 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
          {t('chat.send')}
        </button>
      </form>
    </section>
  );
};

export default AgentChat;
