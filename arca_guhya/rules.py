"""Detection rules.

Each rule is a regular expression whose first capture group (or whole match
when there is no group) is the secret value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str
    pattern: re.Pattern
    redact: bool = True

    def to_dict(self) -> dict:
        return {"id": self.id, "description": self.description, "severity": self.severity}


def _r(rule_id, description, severity, regex, flags=0, redact=True):
    return Rule(rule_id, description, severity, re.compile(regex, flags), redact)


RULES: list[Rule] = [
    _r("private-key", "Private key block", "critical",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |SSH2 ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
       redact=False),
    _r("aws-access-key-id", "AWS access key ID", "high",
       r"(?<![A-Z0-9])((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?![A-Z0-9])"),
    _r("aws-secret-access-key", "AWS secret access key", "critical",
       r"aws.{0,20}?(?:secret|sk).{0,20}?[\s'\"=:]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", re.IGNORECASE),
    _r("github-token", "GitHub token (personal, OAuth, app or refresh)", "high",
       r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
    _r("github-fine-grained-pat", "GitHub fine-grained personal access token", "high",
       r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
    _r("gitlab-token", "GitLab personal access token", "high",
       r"\b(glpat-[A-Za-z0-9_\-]{20})\b"),
    _r("slack-token", "Slack token", "high",
       r"\b(xox[abposr]-[0-9A-Za-z\-]{10,250})"),
    _r("slack-webhook", "Slack incoming webhook URL", "medium",
       r"(https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})"),
    _r("stripe-live-key", "Stripe live secret or restricted key", "critical",
       r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b"),
    _r("stripe-test-key", "Stripe test secret key", "low",
       r"\b((?:sk|rk)_test_[0-9a-zA-Z]{24,99})\b"),
    _r("google-api-key", "Google API key", "high",
       r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"),
    _r("npm-token", "npm access token", "high",
       r"\b(npm_[A-Za-z0-9]{36})\b"),
    _r("sendgrid-api-key", "SendGrid API key", "high",
       r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
    _r("twilio-api-key", "Twilio API key SID", "medium",
       r"\b(SK[0-9a-f]{32})\b"),
    _r("jwt", "JSON Web Token", "medium",
       r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"),
    _r("url-credentials", "Password embedded in URL", "high",
       r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@'\"]{1,64}:([^/\s:@'\"]{3,128})@[^\s/'\"]+"),
]

# Not a regex rule: implemented in scanner.py using Shannon entropy.
ENTROPY_RULE = Rule(
    "high-entropy-string", "High-entropy string (possible secret)", "medium",
    re.compile(r"(?:['\"`]|[:=]\s*)([A-Za-z0-9+/_\-]{20,}={0,2})"),
)

SECRET_KEYWORDS = re.compile(r"(?i)(secret|passw|pwd|token|api[_\-]?key|apikey|auth|credential|private|access[_\-]?key)")

ALL_RULES = RULES + [ENTROPY_RULE]


def rule_by_id(rule_id: str) -> Rule | None:
    for rule in ALL_RULES:
        if rule.id == rule_id:
            return rule
    return None


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)
