"""
Sanitizer and Redaction Module for SecureMailScope.
Ensures zero cleartext credentials, auth tokens, passwords, private keys,
or secrets ever reach Gemini prompts, log files, or unredacted persistence.
"""

import re
from typing import Dict, Any, List, Optional, Tuple


# Regex patterns for high-risk sensitive strings
SENSITIVE_PATTERNS = [
    # Private Key blocks
    (re.compile(r'-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]+ PRIVATE KEY-----', re.IGNORECASE), '[REDACTED_PRIVATE_KEY]'),
    # Bearer Tokens / JWTs
    (re.compile(r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', re.IGNORECASE), 'Bearer [REDACTED_BEARER_TOKEN]'),
    # Supabase / OpenAI / Gemini API Keys
    (re.compile(r'(AIza[0-9A-Za-z-_]{35}|AQ\.[A-Za-z0-9_-]{40,}|sk-[a-zA-Z0-9]{20,})'), '[REDACTED_API_KEY]'),
    # Generic password in URIs/JSON
    (re.compile(r'(["\']?password["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
]


class DataSanitizer:
    """Centralized sanitization methods for network forensics and AI boundaries."""

    @staticmethod
    def sanitize_text(text: str) -> str:
        """Applies global regex redactions to arbitrary text."""
        if not text:
            return ""
        sanitized = str(text)
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    @staticmethod
    def sanitize_for_gemini(data: Any) -> Any:
        """
        Recursively traverses findings/dictionaries ensuring no raw PCAP payload
        or credentials reach AI prompt inputs.
        """
        if isinstance(data, str):
            return DataSanitizer.sanitize_text(data)
        elif isinstance(data, list):
            return [DataSanitizer.sanitize_for_gemini(item) for item in data]
        elif isinstance(data, dict):
            # Whitelist-based or sanitized key inspection
            sanitized_dict = {}
            for k, v in data.items():
                # Never pass raw hex or binary payloads to Gemini
                if k in ['hex_payload', 'payload_hex', 'der_bytes', 'raw_bytes', 'tcp_payload']:
                    continue
                sanitized_dict[k] = DataSanitizer.sanitize_for_gemini(v)
            return sanitized_dict
        return data

    @staticmethod
    def redact_mail_credentials(text: str, direction: str, protocol: str, state: Optional[str] = None) -> Tuple[str, int, Optional[str]]:
        """
        Protocol-aware credential redaction for email protocols (SMTP, POP3, IMAP).
        """
        redactions = 0
        new_state = state
        lines = text.split('\r\n')
        processed_lines = []

        for line in lines:
            trimmed = line.strip()

            # 1. SMTP AUTH PLAIN
            if direction == 'client_to_server' and trimmed.upper().startswith('AUTH PLAIN'):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    line = f"{parts[0]} {parts[1]} [REDACTED_PLAIN_CREDENTIALS]"
                    redactions += 1
                else:
                    new_state = 'SMTP_AUTH_PLAIN_WAIT'

            elif direction == 'client_to_server' and state == 'SMTP_AUTH_PLAIN_WAIT':
                line = "[REDACTED_PLAIN_CREDENTIALS]"
                redactions += 1
                new_state = None

            # 2. SMTP AUTH LOGIN
            elif direction == 'client_to_server' and trimmed.upper().startswith('AUTH LOGIN'):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    line = f"{parts[0]} {parts[1]} [REDACTED_USER_BASE64]"
                    redactions += 1
                    new_state = 'SMTP_AUTH_LOGIN_PASS'
                else:
                    new_state = 'SMTP_AUTH_LOGIN_USER'

            elif direction == 'server_to_client' and '334 VXNlcm5hbWU6' in line: # 'Username:' in B64
                new_state = 'SMTP_AUTH_LOGIN_USER'

            elif direction == 'server_to_client' and '334 UGFzc3dvcmQ6' in line: # 'Password:' in B64
                new_state = 'SMTP_AUTH_LOGIN_PASS'

            elif direction == 'client_to_server' and state == 'SMTP_AUTH_LOGIN_USER':
                line = "[REDACTED_USERNAME_BASE64]"
                redactions += 1
                new_state = 'SMTP_AUTH_LOGIN_PASS'

            elif direction == 'client_to_server' and state == 'SMTP_AUTH_LOGIN_PASS':
                line = "[REDACTED_PASSWORD_BASE64]"
                redactions += 1
                new_state = None

            # 3. POP3 USER and PASS
            elif direction == 'client_to_server' and trimmed.upper().startswith('PASS '):
                line = "PASS [REDACTED_PASSWORD]"
                redactions += 1

            # 4. IMAP LOGIN
            elif direction == 'client_to_server' and re.search(r'^[A-Za-z0-9]+\s+LOGIN\s+', trimmed, re.IGNORECASE):
                parts = line.split(maxsplit=3)
                if len(parts) >= 4:
                    line = f"{parts[0]} {parts[1]} {parts[2]} [REDACTED_PASSWORD]"
                    redactions += 1

            # 5. Bearer / OAuth Tokens
            elif 'Bearer ' in line:
                line = re.sub(r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer [REDACTED_BEARER_TOKEN]', line)
                redactions += 1

            processed_lines.append(line)

        return '\r\n'.join(processed_lines), redactions, new_state
