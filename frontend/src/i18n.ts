import { useCallback, useState } from 'react';
import en from './locales/en.json';
import hi from './locales/hi.json';
import te from './locales/te.json';

export type Language = 'en' | 'hi' | 'te';
export type TranslateParams = Record<string, string | number>;
export type Translator = (key: string, params?: TranslateParams) => string;
type TranslationDictionary = Record<string, any>;

const translations: Record<Language, TranslationDictionary> = {
  en,
  hi,
  te,
};

function readSavedLanguage(): Language {
  try {
    const saved = localStorage.getItem('findout-language');
    if (saved === 'en' || saved === 'hi' || saved === 'te') {
      return saved;
    }
  } catch {
    // Storage may be disabled; use English.
  }

  return 'en';
}

function lookup(
  dictionary: TranslationDictionary,
  path: string,
): unknown {
  return path.split('.').reduce<unknown>((value, key) => {
    if (
      value !== null &&
      typeof value === 'object' &&
      key in (value as Record<string, unknown>)
    ) {
      return (value as Record<string, unknown>)[key];
    }
    return undefined;
  }, dictionary);
}

function interpolate(text: string, params?: TranslateParams): string {
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
}

export function createTranslator(language: Language): Translator {
  return (key: string, params?: TranslateParams): string => {
    const translated = lookup(translations[language], key);

    if (typeof translated === 'string') {
      return interpolate(translated, params);
    }

    const fallback = lookup(translations.en, key);
    return typeof fallback === 'string' ? interpolate(fallback, params) : key;
  };
}

export function useTranslation() {
  const [language, setLanguageState] = useState<Language>(readSavedLanguage);

  const setLanguage = useCallback((nextLanguage: Language) => {
    setLanguageState(nextLanguage);

    try {
      localStorage.setItem('findout-language', nextLanguage);
    } catch {
      // Language still changes for this session if storage is unavailable.
    }
  }, []);

  const t = createTranslator(language);

  return {
    t,
    language,
    currentLang: language,
    setLanguage,
  };
}

export default useTranslation;
