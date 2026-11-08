from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


def has_permission(user, code):
    """Retired prototype API: global role rows never authorize tenant operations.

    Use platform_core.services.authorize for built-ins and extensions.api.authorize
    for signed extension permissions. Neither can infer an organization from a
    historical global BusinessRole.
    """
    return False


def require_permission(code):
    def decorator(view):
        @login_required
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if not has_permission(request.user, code):
                raise PermissionDenied("Permission PAM-olive insuffisante.")
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
