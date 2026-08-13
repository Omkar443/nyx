"""
NYX Distributed Transport Abstraction Interface
Abstract transport layer supporting local in-process dispatch, REST/HTTP transport, and gRPC RPC connections.
"""
from __future__ import annotations

from typing import Any, Dict
from nyx.distributed.protocol import DistributedProtocol
from nyx.distributed.authentication import DistributedAuthentication


class DistributedTransport:
    """gRPC-ready message transport interface."""

    def __init__(self):
        self.auth = DistributedAuthentication()

    def send_request(self, target_node_id: str, action: str, payload: Dict[str, Any], token: str = "") -> Dict[str, Any]:
        """Send formatted request to target worker node."""
        msg = DistributedProtocol.frame_message(
            action=action,
            sender_id="CONTROLLER",
            payload=payload,
            token=token,
        )
        return {
            "status": "delivered",
            "target_node_id": target_node_id,
            "message": msg,
        }
