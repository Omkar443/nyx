export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  error?: string | null;
  code?: string;
}

const API_BASE = '';
let inMemoryToken: string = '';
let authInitPromise: Promise<string> | null = null;

export function getStoredToken(): string {
  if (inMemoryToken) {
    return inMemoryToken;
  }

  // 1. Check URL parameters
  if (typeof window !== 'undefined') {
    const params = new URLSearchParams(window.location.search);
    const tokenParam = params.get('token') || params.get('api_token');
    if (tokenParam && tokenParam.trim()) {
      setStoredToken(tokenParam.trim());
      return tokenParam.trim();
    }
  }

  // 2. Check localStorage (avoid hardcoded legacy placeholder)
  if (typeof window !== 'undefined') {
    const saved = localStorage.getItem('nyx_api_token');
    if (saved && saved.trim() && saved !== 'nyx-local-token') {
      inMemoryToken = saved.trim();
      return inMemoryToken;
    }
  }

  // 3. Check environment variable
  const envToken = (import.meta.env as any)?.VITE_NYX_API_TOKEN;
  if (envToken && typeof envToken === 'string' && envToken.trim()) {
    setStoredToken(envToken.trim());
    return envToken.trim();
  }

  return '';
}

export function setStoredToken(token: string): void {
  inMemoryToken = token;
  if (typeof window !== 'undefined' && token) {
    localStorage.setItem('nyx_api_token', token);
  }
}

export async function initAuth(forceRefresh: boolean = false): Promise<string> {
  if (!forceRefresh) {
    const existing = getStoredToken();
    if (existing) {
      return existing;
    }
  }

  if (authInitPromise) {
    return authInitPromise;
  }

  authInitPromise = (async () => {
    try {
      const endpoints = ['/api/v1/auth/token', '/health', '/api/v1/health'];
      for (const ep of endpoints) {
        try {
          const res = await fetch(ep);
          if (res.ok) {
            const data = await res.json();
            const tok = data?.api_token || data?.token;
            if (tok && typeof tok === 'string') {
              setStoredToken(tok.trim());
              return tok.trim();
            }
          }
        } catch {
          // ignore endpoint error and try next
        }
      }
    } catch (err) {
      // Ignore network errors during background token resolution
    }
    return getStoredToken();
  })();

  try {
    return await authInitPromise;
  } finally {
    authInitPromise = null;
  }
}

export async function fetchApi<T = any>(endpoint: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
  let token = getStoredToken();
  if (!token && !endpoint.includes('/auth/') && !endpoint.includes('/health')) {
    token = await initAuth();
  }

  const headers = new Headers(options.headers || {});
  
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }
  
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
    headers.set('X-API-Token', token);
  }

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (res.status === 401) {
      const freshToken = await initAuth(true);
      if (freshToken && freshToken !== token) {
        headers.set('Authorization', `Bearer ${freshToken}`);
        headers.set('X-API-Token', freshToken);
        const retryRes = await fetch(`${API_BASE}${endpoint}`, {
          ...options,
          headers,
        });
        if (retryRes.ok) {
          return await retryRes.json();
        }
      }
      return {
        success: false,
        data: {} as T,
        error: 'Unauthorized: Invalid API token.',
        code: 'UNAUTHORIZED',
      };
    }

    const data = await res.json();
    return data;
  } catch (err: any) {
    return {
      success: false,
      data: {} as T,
      error: err.message || 'Network request failed',
      code: 'NETWORK_ERROR',
    };
  }
}
