import ipaddress

from django.conf import settings


class TrustedProxyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            peer = ipaddress.ip_address(request.META.get("REMOTE_ADDR"))
            trusted = any(
                peer in ipaddress.ip_network(value) for value in settings.PAM_TRUSTED_PROXY_NETWORKS
            )
        except ValueError:
            trusted = False
        if not trusted:
            request.META.pop("HTTP_X_FORWARDED_PROTO", None)
            request.META.pop("HTTP_X_FORWARDED_FOR", None)
        return self.get_response(request)


class ResponseSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response["Referrer-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        if getattr(request, "user", None) and request.user.is_authenticated:
            response["Cache-Control"] = "no-store"
        return response
