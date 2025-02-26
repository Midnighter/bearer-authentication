# Copyright 2020 Novo Nordisk Foundation Center for Biosustainability,
# Technical University of Denmark.
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


"""Test the response generated by the client."""


import json
import os
from urllib.error import HTTPError
from urllib.parse import urljoin
from urllib.request import HTTPPasswordMgrWithDefaultRealm, build_opener

import pytest

from http_bearer_auth_handler import HTTPBearerAuthHandler


@pytest.fixture(scope="module")
def api() -> str:
    return urljoin(os.getenv("HTTPBIN_URL", "https://httpbin.org"), "/bearer")


def test_httpbin_bearer_authentication_success(api: str) -> None:
    """Test that the response has the expected status code."""
    password_manager = HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(
        None,  # type: ignore
        api,
        "",
        "secure_token",
    )
    opener = build_opener()
    opener.add_handler(HTTPBearerAuthHandler(password_mgr=password_manager))
    with opener.open(api) as response:
        assert response.status == 200
        assert json.loads(response.read())["token"] == "secure_token"
