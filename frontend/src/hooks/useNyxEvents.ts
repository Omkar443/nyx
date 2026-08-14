import { useEffect, useRef, useState } from 'react';
import { getStoredToken, initAuth } from '../api/client';

export interface NyxEvent {
  event: string;
  timestamp: string;
  mission_id?: string;
  data: Record<string, any>;
}

export function useNyxEvents() {
  const [connected, setConnected] = useState<boolean>(false);
  const [lastEvent, setLastEvent] = useState<NyxEvent | null>(null);
  const [eventsHistory, setEventsHistory] = useState<NyxEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let active = true;
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
    let retryAttempts = 0;
    const MAX_RETRIES = 5;

    async function connect(forceRefresh: boolean = false) {
      if (!active) return;
      
      // Ensure authoritative active token from backend (force refresh on retry or auth failure)
      const token = await initAuth(forceRefresh || retryAttempts > 0);
      if (!active) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host || '127.0.0.1:8000';
      const wsUrl = `${protocol}//${host}/ws/events?token=${encodeURIComponent(token || '')}`;

      try {
        if (wsRef.current) {
          try { wsRef.current.close(); } catch {}
        }

        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          if (active) {
            setConnected(true);
            retryAttempts = 0; // reset retry counter on successful connection
          }
        };

        ws.onmessage = (evt) => {
          if (!active) return;
          try {
            if (evt.data === 'pong') return;
            const parsed: NyxEvent = JSON.parse(evt.data);
            setLastEvent(parsed);
            setEventsHistory((prev) => [parsed, ...prev.slice(0, 49)]);
          } catch (e) {
            // silent parse fallback
          }
        };

        ws.onclose = (evt) => {
          if (!active) return;
          setConnected(false);
          
          // Detect policy violation (1008 / 4003) or auth rejection
          const isAuthError = evt.code === 1008 || evt.code === 4003;
          if (retryAttempts < MAX_RETRIES) {
            retryAttempts++;
            const delay = isAuthError ? 1000 : Math.min(1000 * Math.pow(2, retryAttempts), 10000);
            reconnectTimeout = setTimeout(() => {
              if (active) connect(true);
            }, delay);
          }
        };

        ws.onerror = () => {
          try { ws.close(); } catch {}
        };

        wsRef.current = ws;
      } catch (e) {
        if (active && retryAttempts < MAX_RETRIES) {
          retryAttempts++;
          reconnectTimeout = setTimeout(() => {
            if (active) connect(true);
          }, 3000);
        }
      }
    }

    connect(false);

    return () => {
      active = false;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (wsRef.current) {
        try { wsRef.current.close(); } catch {}
      }
    };
  }, []);

  return { connected, lastEvent, eventsHistory };
}
