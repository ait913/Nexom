from nexom.app.request import Request
from nexom.app.response import Response, HtmlResponse

from nexom.app.auth import AuthClient, KEY_NAME

from __app_name__.config import AUTH_SERVER
from ._templates import templates


def main(request: Request, args: dict) -> Response:
    ac = AuthClient(AUTH_SERVER)

    # Get login token from request cookies
    token = request.cookie.get(KEY_NAME) if request.cookie else None
    # Verify with the authentication server
    session = ac.verify_token(token) if token else None

    if session:
        msg = f"Hello <i>{session.public_name}@{session.user_id}</i> San!!"
    else:
        msg = "Not Logined." 

    return HtmlResponse(
        templates.render("default", title="Nexom Default Page", user_message=msg)
    )