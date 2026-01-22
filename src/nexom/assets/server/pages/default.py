from nexom.web.request import Request
from nexom.web.response import Response

from ._templates import templates


def main(request: Request, args: dict) -> Response:
    return Response(
        templates.default(title="Nexom Default Page")
    )