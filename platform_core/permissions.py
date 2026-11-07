from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


def has_permission(user, code):
    if user.is_superuser:
        return True
    return user.pamolive_business_roles.filter(permission_grants__code=code).exists()


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
