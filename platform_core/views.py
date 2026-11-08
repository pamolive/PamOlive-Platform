"""Import-compatible tombstones for the retired, installation-global prototype.

Current organization-scoped routes live in platform_modules.access.ui and domain views.
Historical tables remain readable to the backup verifier, never an authorization source.
"""

from django.http import HttpResponseGone


def retired_view(request, *args, **kwargs):
    response = HttpResponseGone("Cette interface du prototype a été retirée.")
    response["Cache-Control"] = "no-store"
    return response


retired_view.pamolive_retired_route = True

dashboard = user_list = user_create = user_edit = retired_view
role_list = role_create = role_edit = retired_view
module_list = module_install = module_disable = retired_view
audit_log = system_status = retired_view


def module_is_enabled(module_key):
    return False


def installed_module_required(module_key):
    # Old IAM views import this decorator. Even accidental routing must not read
    # global applications/accounts or change legacy activation state.
    return lambda view: retired_view
