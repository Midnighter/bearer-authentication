# Copyright (c) 2020, Moritz E. Beber.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


""""""


import logging
import re
import warnings
from typing import Tuple, Optional, Iterator
from urllib.request import BaseHandler, HTTPPasswordMgr


logger = logging.getLogger(__name__)


class AbstractBearerAuthHandler(BaseHandler):

    # XXX this allows for multiple auth-schemes, but will stupidly pick
    # the last one with a realm specified.

    # allow for double- and single-quoted realm values
    # (single quotes are a violation of the RFC, but appear in the wild)
    rx = re.compile('(?:^|,)'  # start of the string or ','
                    '[ \t]*'  # optional whitespaces
                    '([^ \t]+)'  # scheme like "Basic"
                    '[ \t]+'  # mandatory whitespaces
                    # realm=xxx
                    # realm='xxx'
                    # realm="xxx"
                    'realm=(["\']?)([^"\']*)\\2',
                    re.I)
    auth_header = "Authorization"

    # XXX could pre-emptively send auth info already accepted (RFC 2617,
    # end of section 2, and section 1.2 immediately after "credentials"
    # production).

    def __init__(self, password_mgr: HTTPPasswordMgr = None, **kwargs) -> None:
        """"""
        super().__init__(**kwargs)
        self.passwd = HTTPPasswordMgr() if password_mgr is None else password_mgr

    def add_password(self, realm, uri, user, passwd) -> None:
        self.passwd.add_password(realm, uri, user, passwd)

    def _add_credentials(self, request, token) -> None:
        credentials = f"Bearer {token}"
        if request.get_header(self.auth_header, "") != credentials:
            request.add_unredirected_header(self.auth_header, credentials)

    def _parse_realm(self, header) -> Iterator[Tuple[str, Optional[str]]]:
        # parse WWW-Authenticate header: accept multiple challenges per header
        found_challenge = False
        for mo in self.rx.finditer(header):
            scheme, quote, realm = mo.groups()
            if quote not in ['"', "'"]:
                warnings.warn(
                    "Bearer authentication realm was unquoted", UserWarning, 3
                )
            yield scheme.lower(), realm
            found_challenge = True

        if not found_challenge:
            if header:
                scheme = header.split()[0]
            else:
                scheme = ''
            yield scheme.lower(), None

    def http_error_auth_reqed(self, authreq, host, req, headers):
        logger.debug("Bearer authentication requested.")
        headers = headers.get_all(authreq)
        if not headers:
            # no header found
            return
        unsupported = set()
        for header in headers:
            logger.debug("Challenge header: %s", header)
            for scheme, realm in self._parse_realm(header):
                if scheme != "bearer":
                    unsupported.add(scheme)
                    continue
                if realm is not None:
                    # Use the first matching Bearer challenge. Ignore following
                    # challenges even if they use the Bearer scheme.
                    return self.retry_http_bearer_authentication(host, req, realm)
                else:
                    logger.error(
                        "Bearer authentication challenge is missing a realm "
                        "description. Found: %r", header
                    )
        if unknown := unsupported.difference({"basic", "digest"}):
            raise ValueError(
                f"AbstractBearerAuthHandler does not "
                f" support the following scheme(s): {', '.join(unknown)}"
            )

    def retry_http_bearer_authentication(self, host, req, realm):
        logger.debug("Retrying Bearer authentication...")
        _, token = self.passwd.find_user_password(realm, host)
        if token is not None:
            self._add_credentials(req, token)
            return self.parent.open(req, timeout=req.timeout)
        else:
            return None

    def http_request(self, req):
        logger.debug("In http_request.")
        if not hasattr(
            self.passwd, "is_authenticated"
        ) or not self.passwd.is_authenticated(req.full_url):
            return req

        if not req.has_header(self.auth_header):
            _, token = self.passwd.find_user_password(None, req.full_url)  # type: ignore
            self._add_credentials(req, token)
        return req

    def http_response(self, req, response):
        logger.debug("In http_response.")
        if hasattr(self.passwd, "is_authenticated"):
            if 200 <= response.code < 300:
                self.passwd.update_authenticated(req.full_url, True)
            else:
                self.passwd.update_authenticated(req.full_url, False)
        return response

    https_request = http_request
    https_response = http_response


class HTTPBearerAuthHandler(AbstractBearerAuthHandler):

    handler_order = 480  # Before a possible Digest authentication handler.

    def http_error_401(self, request, _fp, _code, _msg, headers):
        logger.debug("Handling 401.")
        url = request.full_url
        response = self.http_error_auth_reqed("www-authenticate", url, request, headers)
        return response
