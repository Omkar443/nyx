"""
NYX Distributed Communication Protocol
Defines structured message frames and serialization for inter-node communication.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict


class DistributedProtocol:
    """Serializes and frames inter-node RPC messages."""

    @staticmethod
    def frame_message(
        action: str,
        sender_id: str,
        payload: Dict[str, Any],
        token: str = "",
    ) -> Dict[str, Any]:
        return {
            "version": "1.0",
            "action": action,
            "sender_id": sender_id,
            "token": token,
            "payload": payload,
            "timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def parse_message(raw_json: str) -> Dict[str, Any]:
        try:
            return json.loads(raw_json)
        except Exception as e:
            return {"error": f"Failed to parse JSON protocol message: {e}"}
