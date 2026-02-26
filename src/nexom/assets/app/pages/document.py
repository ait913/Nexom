"""Document page handler template."""

from nexom.app.request import Request
from nexom.app.response import HtmlResponse

from ._templates import templates


def main(request: Request, args: dict) -> HtmlResponse:
    return HtmlResponse(
        templates.document(title="Nexom Documents")
    )