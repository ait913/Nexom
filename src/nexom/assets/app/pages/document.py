from nexom.app.request import Request
from nexom.app.response import Response

from ._templates import templates


def main(request: Request, args: dict) -> Response:
    return Response(
        templates.document(title="Nexom Documents")
    )