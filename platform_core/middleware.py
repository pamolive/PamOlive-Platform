class ResponseSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response["Referrer-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        if getattr(request, "user", None) and request.user.is_authenticated:
            response["Cache-Control"] = "no-store"
        return response
