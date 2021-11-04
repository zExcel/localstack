import requests.models
from werkzeug.datastructures import Headers

from localstack.aws.api import HttpRequest, HttpResponse
from localstack.aws.gateway import Gateway
from localstack.constants import HEADER_LOCALSTACK_REQUEST_URL
from localstack.utils.common import path_from_url


class LocalstackHttp2Adapter:
    gateway: Gateway

    def __init__(self, gateway: Gateway) -> None:
        super().__init__()
        self.gateway = gateway

    def __call__(self, request, data):
        return self.handler(request, data)

    def handler(self, request, data):
        # create framework HttpRequest
        path_with_params = path_from_url(request.url)
        method = request.method
        headers = Headers(request.headers)
        headers[HEADER_LOCALSTACK_REQUEST_URL] = str(request.url)

        http_request = HttpRequest(
            path=path_with_params,
            method=method,
            headers=headers,
            body=data,
        )

        http_response = HttpResponse(headers=dict(), body=b"", status_code=0)

        self.gateway.process(http_request, http_response)

        return self.to_server_response(http_response)

    def to_server_response(self, response: HttpResponse):
        # TODO: creating response objects in this way (re-using the requests library instead of an HTTP server
        #  framework) is a bit ugly, but it's the way that the edge proxy expects them.
        resp = requests.models.Response()
        resp._content = response["body"]
        resp.status_code = response["status_code"]
        resp.headers.update(response["headers"])
        resp.headers["Content-Length"] = str(len(response["body"]))
        return resp
