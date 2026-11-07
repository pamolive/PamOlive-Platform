import os
import uuid

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django_application = get_asgi_application()


async def application(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            event = await receive()
            if event["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif event["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    elif scope["type"] == "websocket":
        from platform_modules.pam.broker import Relay

        parts = scope.get("path", "").split("/")
        try:
            if len(parts) != 5 or parts[1:3] != ["ws", "pam"] or parts[4] != "":
                raise ValueError
            connection_id = uuid.UUID(parts[3])
        except ValueError:
            await send({"type": "websocket.close", "code": 4404})
            return
        await Relay(connection_id, scope, receive, send).run()
    else:
        await django_application(scope, receive, send)
