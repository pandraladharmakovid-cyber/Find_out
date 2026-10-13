
const configuredBaseUrl = import.meta.env.VITE_API_URL?.trim();

function resolveDefaultApiBase(): string {
  if (typeof window !== 'undefined') {
    const origin = window.location.origin;
    const pathname = window.location.pathname;

    // Detect if running behind ByteXL / Nimbus proxy (/proxy/<port>/)
    if (pathname.includes('/proxy/')) {
      return `${origin}/proxy/5000/api`;
    }
  }
  return 'http://localhost:5000/api';
}

const API_BASE = (
  configuredBaseUrl || resolveDefaultApiBase()
).replace(/\/+$/, '');


export class ApiError extends Error {
  readonly status: number;
  readonly details: unknown;

  constructor(message: string, status = 0, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

type ApiRequestOptions = RequestInit & {
  timeoutMs?: number;
};

function isFormData(body: BodyInit | null | undefined): boolean {
  return typeof FormData !== 'undefined' && body instanceof FormData;
}

function isJsonContentType(value: string | null): boolean {
  return Boolean(value?.toLowerCase().includes('application/json'));
}

async function readResponse(response: Response): Promise<unknown> {
  if (response.status === 204) return null;

  const contentType = response.headers.get('content-type');

  if (isJsonContentType(contentType)) {
    return response.json().catch(() => {
      throw new ApiError(
        `The server returned invalid JSON (HTTP ${response.status}).`,
        response.status,
      );
    });
  }

  const text = await response.text().catch(() => '');

  if (!text.trim()) return null;

  try {
    return JSON.parse(text);
  } catch {
    return { message: text.slice(0, 1000) };
  }
}

function getErrorMessage(payload: any, status: number): string {
  if (typeof payload?.error === 'string' && payload.error.trim()) {
    return payload.error;
  }

  if (typeof payload?.message === 'string' && payload.message.trim()) {
    return payload.message;
  }

  if (typeof payload?.details === 'string' && payload.details.trim()) {
    return payload.details;
  }

  if (status === 401) return 'Authentication is required for this request.';
  if (status === 403) return 'You do not have permission to perform this action.';
  if (status === 404) return 'The requested API endpoint was not found.';
  if (status === 408) return 'The request timed out.';
  if (status === 413) return 'The submitted content is too large.';
  if (status === 429) return 'Too many requests. Please try again shortly.';
  if (status >= 500) return 'The server encountered an error. Please try again.';
  if (status > 0) return `Request failed with HTTP ${status}.`;

  return 'Unable to reach the API server. Check that the backend is running and the API URL is correct.';
}

export async function apiRequest<T = any>(
  endpoint: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  const {
    timeoutMs = 20000,
    signal: externalSignal,
    headers: suppliedHeaders,
    ...requestOptions
  } = options;

  const normalizedEndpoint = endpoint.startsWith('/')
    ? endpoint
    : `/${endpoint}`;

  const url = `${API_BASE}${normalizedEndpoint}`;
  const headers = new Headers(suppliedHeaders);

  if (
    requestOptions.body !== undefined &&
    requestOptions.body !== null &&
    !isFormData(requestOptions.body) &&
    !headers.has('Content-Type')
  ) {
    headers.set('Content-Type', 'application/json');
  }

  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  const controller = new AbortController();
  let timedOut = false;

  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const forwardAbort = () => controller.abort();

  if (externalSignal) {
    if (externalSignal.aborted) {
      controller.abort();
    } else {
      externalSignal.addEventListener('abort', forwardAbort, { once: true });
    }
  }

  try {
    let response: Response;

    try {
      response = await fetch(url, {
        ...requestOptions,
        headers,
        signal: controller.signal,
      });
    } catch (error) {
      if (timedOut) {
        throw new ApiError(
          `The request timed out after ${Math.round(timeoutMs / 1000)} seconds.`,
        );
      }

      if (externalSignal?.aborted) {
        throw new ApiError('The request was cancelled.');
      }

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        'Unable to connect to the API server. Check the backend, port, and CORS configuration.',
      );
    }

    const payload = await readResponse(response);

    if (!response.ok) {
      throw new ApiError(
        getErrorMessage(payload, response.status),
        response.status,
        payload,
      );
    }

    return payload as T;
  } finally {
    clearTimeout(timeoutId);
    externalSignal?.removeEventListener('abort', forwardAbort);
  }
}

export function getApiBaseUrl(): string {
  return API_BASE;
}
