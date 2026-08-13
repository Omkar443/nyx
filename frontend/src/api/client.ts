export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  error?: string | null;
  code?: string;
}

const API_BASE = '';

export function getStoredToken(): string {
  return localStorage.getItem('nyx_api_token') || 'nyx-local-token';
}

export function setStoredToken(token: string): void {
  localStorage.setItem('nyx_api_token', token);
}

export async function fetchApi<T = any>(endpoint: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
  const token = getStoredToken();
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
