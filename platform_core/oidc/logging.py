import logging


class OIDCQueryRedactor(logging.Filter):
    """Keep route/status observability without authorization codes or OAuth state."""

    def filter(self, record):
        if isinstance(record.args, tuple):
            record.args = tuple(
                value.split("?", 1)[0] + " [OIDC query redacted]"
                if isinstance(value, str) and "/accounts/oidc/" in value and "?" in value
                else value
                for value in record.args
            )
        return True
