"""
Event-Driven Dynamic Protocol State Machine for SecureMailScope (USP 2)

Performs deterministic, per-flow protocol tracking across SMTP, IMAP, and POP3 streams.
Tracks STARTTLS command negotiation, server response status, TLS handshake progression,
and application data isolation with evidence provenance and uncertainty quantification.
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field


class ProtocolState:
    """Explicit per-flow protocol states"""
    INIT = "INIT"
    PLAINTEXT = "PLAINTEXT"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    STARTTLS_ACCEPTED = "STARTTLS_ACCEPTED"
    STARTTLS_REJECTED = "STARTTLS_REJECTED"
    TLS_HANDSHAKE_INIT = "TLS_HANDSHAKE_INIT"
    TLS_HANDSHAKE_PROGRESS = "TLS_HANDSHAKE_PROGRESS"
    TLS_ESTABLISHED = "TLS_ESTABLISHED"
    PLAINTEXT_FALLBACK = "PLAINTEXT_FALLBACK"
    INCOMPLETE_NEGOTIATION = "INCOMPLETE_NEGOTIATION"
    CLOSED = "CLOSED"


class ProtocolEventType:
    """Normalized protocol events emitted by packet and stream parsers"""
    SERVER_BANNER = "SERVER_BANNER"
    CLIENT_EHLO = "CLIENT_EHLO"
    CLIENT_HELO = "CLIENT_HELO"
    STARTTLS_CMD = "STARTTLS_CMD"
    STARTTLS_RESP_220 = "STARTTLS_RESP_220"
    STARTTLS_RESP_ERR = "STARTTLS_RESP_ERR"
    TLS_CLIENT_HELLO = "TLS_CLIENT_HELLO"
    TLS_SERVER_HELLO = "TLS_SERVER_HELLO"
    TLS_CERTIFICATE = "TLS_CERTIFICATE"
    TLS_APPLICATION_DATA = "TLS_APPLICATION_DATA"
    PLAINTEXT_COMMAND = "PLAINTEXT_COMMAND"
    PLAINTEXT_RESPONSE = "PLAINTEXT_RESPONSE"
    CONNECTION_CLOSE = "CONNECTION_CLOSE"
    TCP_RESET = "TCP_RESET"


@dataclass
class ProtocolEvent:
    """Normalized event observed from packet capture evidence"""
    frame_number: int
    timestamp: Any
    stream_id: int
    event_type: str
    data: str = ""
    evidence_ref: Optional[str] = None

    def __post_init__(self):
        if not self.evidence_ref:
            self.evidence_ref = f"frame_{self.frame_number}"


class FlowStateMachine:
    """
    State machine for an isolated TCP flow/stream.
    Processes chronological protocol events and maintains verifiable state transitions.
    """

    def __init__(self, stream_id: int, flow_id: str, protocol: str = "SMTP"):
        self.stream_id = stream_id
        self.flow_id = flow_id
        self.protocol = protocol
        self.current_state = ProtocolState.INIT
        self.transition_history: List[Dict[str, Any]] = []
        self.events: List[ProtocolEvent] = []
        self.seen_frames: Set[int] = set()
        self.has_starttls_requested = False
        self.has_starttls_accepted = False
        self.has_starttls_rejected = False

    def process_event(self, event: ProtocolEvent) -> Dict[str, Any]:
        """
        Processes a single protocol event in chronological stream order.
        Validates the event against the current state and records transition evidence.
        """
        self.events.append(event)
        prev_state = self.current_state
        event_type = event.event_type
        new_state = prev_state
        reason = "State preserved"
        is_valid = True

        # State transition logic
        if self.current_state == ProtocolState.INIT:
            if event_type in (ProtocolEventType.SERVER_BANNER, ProtocolEventType.CLIENT_EHLO,
                              ProtocolEventType.CLIENT_HELO, ProtocolEventType.PLAINTEXT_COMMAND):
                new_state = ProtocolState.PLAINTEXT
                reason = "Stream initialized with plaintext banner or command"
            elif event_type == ProtocolEventType.STARTTLS_CMD:
                new_state = ProtocolState.STARTTLS_REQUESTED
                self.has_starttls_requested = True
                reason = "STARTTLS requested immediately upon stream open"
            elif event_type == ProtocolEventType.TLS_CLIENT_HELLO:
                new_state = ProtocolState.TLS_HANDSHAKE_INIT
                reason = "Direct TLS handshake initiated on stream"
            elif event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.CLOSED
                reason = "Connection terminated in INIT state"

        elif self.current_state == ProtocolState.PLAINTEXT:
            if event_type == ProtocolEventType.STARTTLS_CMD:
                new_state = ProtocolState.STARTTLS_REQUESTED
                self.has_starttls_requested = True
                reason = "STARTTLS upgrade command issued by client"
            elif event_type == ProtocolEventType.TLS_CLIENT_HELLO:
                new_state = ProtocolState.TLS_HANDSHAKE_INIT
                reason = "TLS handshake observed without explicit STARTTLS negotiation (anomaly/direct)"
            elif event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.CLOSED
                reason = "Connection terminated in plaintext"

        elif self.current_state == ProtocolState.STARTTLS_REQUESTED:
            if event_type == ProtocolEventType.STARTTLS_RESP_220:
                new_state = ProtocolState.STARTTLS_ACCEPTED
                self.has_starttls_accepted = True
                reason = "Server acknowledged STARTTLS with 220 Ready"
            elif event_type == ProtocolEventType.STARTTLS_RESP_ERR:
                new_state = ProtocolState.STARTTLS_REJECTED
                self.has_starttls_rejected = True
                reason = "Server rejected STARTTLS request"
            elif event_type == ProtocolEventType.TLS_CLIENT_HELLO:
                # Capture missing server 220 response, but client started TLS
                new_state = ProtocolState.TLS_HANDSHAKE_INIT
                reason = "TLS ClientHello observed after STARTTLS command without captured 220"
            elif event_type == ProtocolEventType.PLAINTEXT_COMMAND:
                new_state = ProtocolState.PLAINTEXT_FALLBACK
                reason = "Client continued with plaintext commands without waiting for STARTTLS response"
            elif event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.INCOMPLETE_NEGOTIATION
                reason = "Connection closed before STARTTLS response"

        elif self.current_state == ProtocolState.STARTTLS_ACCEPTED:
            if event_type == ProtocolEventType.TLS_CLIENT_HELLO:
                new_state = ProtocolState.TLS_HANDSHAKE_INIT
                reason = "Client started TLS handshake after accepted STARTTLS"
            elif event_type in (ProtocolEventType.PLAINTEXT_COMMAND, ProtocolEventType.PLAINTEXT_RESPONSE):
                new_state = ProtocolState.PLAINTEXT_FALLBACK
                is_valid = False
                reason = "Plaintext transmitted after STARTTLS upgrade accepted (security violation)"
            elif event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.INCOMPLETE_NEGOTIATION
                reason = "Connection closed after STARTTLS accepted before TLS handshake"

        elif self.current_state == ProtocolState.STARTTLS_REJECTED:
            if event_type in (ProtocolEventType.PLAINTEXT_COMMAND, ProtocolEventType.PLAINTEXT_RESPONSE):
                new_state = ProtocolState.PLAINTEXT_FALLBACK
                reason = "Session continued in plaintext after STARTTLS rejection"
            elif event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.CLOSED
                reason = "Connection closed after STARTTLS rejection"

        elif self.current_state == ProtocolState.TLS_HANDSHAKE_INIT:
            if event_type in (ProtocolEventType.TLS_SERVER_HELLO, ProtocolEventType.TLS_CERTIFICATE):
                new_state = ProtocolState.TLS_HANDSHAKE_PROGRESS
                reason = "Server responded with ServerHello / Certificate"
            elif event_type == ProtocolEventType.TLS_APPLICATION_DATA:
                new_state = ProtocolState.TLS_ESTABLISHED
                reason = "Encrypted TLS application data observed"
            elif event_type in (ProtocolEventType.PLAINTEXT_COMMAND, ProtocolEventType.PLAINTEXT_RESPONSE):
                new_state = ProtocolState.PLAINTEXT_FALLBACK
                is_valid = False
                reason = "Plaintext observed during TLS handshake (downgrade/anomaly)"
            elif event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.INCOMPLETE_NEGOTIATION
                reason = "Connection closed during TLS handshake"

        elif self.current_state == ProtocolState.TLS_HANDSHAKE_PROGRESS:
            if event_type == ProtocolEventType.TLS_APPLICATION_DATA:
                new_state = ProtocolState.TLS_ESTABLISHED
                reason = "TLS Handshake completed; encrypted Application Data transferred"
            elif event_type in (ProtocolEventType.TLS_SERVER_HELLO, ProtocolEventType.TLS_CERTIFICATE):
                new_state = ProtocolState.TLS_HANDSHAKE_PROGRESS
                reason = "Continued TLS handshake exchange"
            elif event_type in (ProtocolEventType.PLAINTEXT_COMMAND, ProtocolEventType.PLAINTEXT_RESPONSE):
                new_state = ProtocolState.PLAINTEXT_FALLBACK
                is_valid = False
                reason = "Plaintext observed during TLS handshake"
            elif event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.INCOMPLETE_NEGOTIATION
                reason = "Connection closed before TLS handshake completed"

        elif self.current_state == ProtocolState.TLS_ESTABLISHED:
            if event_type == ProtocolEventType.TLS_APPLICATION_DATA:
                new_state = ProtocolState.TLS_ESTABLISHED
                reason = "Encrypted Application Data transfer"
            elif event_type in (ProtocolEventType.PLAINTEXT_COMMAND, ProtocolEventType.PLAINTEXT_RESPONSE):
                new_state = ProtocolState.PLAINTEXT_FALLBACK
                is_valid = False
                reason = "Plaintext leak detected in established TLS session"
            elif event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.CLOSED
                reason = "TLS session cleanly terminated"

        elif self.current_state in (ProtocolState.PLAINTEXT_FALLBACK, ProtocolState.CLOSED, ProtocolState.INCOMPLETE_NEGOTIATION):
            if event_type in (ProtocolEventType.CONNECTION_CLOSE, ProtocolEventType.TCP_RESET):
                new_state = ProtocolState.CLOSED
                reason = "Stream closed"

        self.current_state = new_state
        record = {
            "stream_id": self.stream_id,
            "flow_id": self.flow_id,
            "from_state": prev_state,
            "to_state": self.current_state,
            "event_type": event_type,
            "data": event.data,
            "evidence_ref": event.evidence_ref,
            "frame_number": event.frame_number,
            "timestamp": str(event.timestamp),
            "reason": reason,
            "valid": is_valid
        }
        self.transition_history.append(record)
        return record

    def get_cryptographic_posture(self) -> Dict[str, Any]:
        """
        Derives the flow's final cryptographic posture from accumulated state evidence.
        """
        is_encrypted = self.current_state == ProtocolState.TLS_ESTABLISHED or (
            self.current_state in (ProtocolState.TLS_HANDSHAKE_INIT, ProtocolState.TLS_HANDSHAKE_PROGRESS)
        )

        has_upgraded = any(
            t["from_state"] == ProtocolState.STARTTLS_ACCEPTED or
            (t["to_state"] == ProtocolState.TLS_ESTABLISHED and self.has_starttls_accepted)
            for t in self.transition_history
        )

        if is_encrypted and has_upgraded:
            starttls_status = "UPGRADED_SUCCESSFUL"
        elif self.current_state == ProtocolState.STARTTLS_REJECTED or self.has_starttls_rejected:
            starttls_status = "REJECTED"
        elif self.has_starttls_requested and not is_encrypted:
            starttls_status = "INCOMPLETE"
        elif self.protocol in ("SMTPS", "IMAPS", "POP3S") or (is_encrypted and not self.has_starttls_requested):
            starttls_status = "NOT_APPLICABLE"
        else:
            starttls_status = "NOT_ATTEMPTED"

        return {
            "stream_id": self.stream_id,
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "current_state": self.current_state,
            "is_encrypted": is_encrypted,
            "starttls_status": starttls_status,
            "total_events": len(self.events),
            "transitions_count": len(self.transition_history),
            "transition_history": self.transition_history
        }
