import logging


class LogHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger(__name__)

    def __call__(self, request):
        headers = dict(request.headers)
        self.logger.info("Request Headers: %s", headers)
        return self.get_response(request)
