import { useEffect, useRef, useState } from 'react';
import { getStoredToken } from '../api/client';

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
    const token = getStoredToken();
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || '127.0.0.1:8000';
    const wsUrl = `${protocol}//${host}/ws/events?token=${encodeURIComponent(token)}`;

    let active = true;

    function connect() {
      if (!active) return;
      try {
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          if (active) setConnected(true);
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

        ws.onclose = () => {
          if (active) {
            setConnected(false);
            setTimeout(connect, 3000);
          }
        };

        ws.onerror = () => {
          ws.close();
        };

        wsRef.current = ws;
      } catch (e) {
        if (active) setTimeout(connect, 5000);
      }
    }

    connect();

    return () => {
      active = false;
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  return { connected, lastEvent, eventsHistory };
}
