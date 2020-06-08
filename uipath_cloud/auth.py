import logging
import requests
from requests.adapters import HTTPAdapter
from datetime import datetime, timedelta

from .exceptions import BadInputException, AuthError, UiPathException
from .constants import UIPATH_AUTH_URLS

TOKEN_EXPIRATION_BUFFER = 300


class TokenUpdated(Warning):
    def __init__(self, token):
        super().__init__()
        self.token = token


class OnPremSession(requests.Session):
    """
    UiPath on prem extension to :class:`requests.Session`

    Supports UiPath on prem Orchestrator installation sessions.
    Username and password authentication for the API calls, returning a Bearer Token

    More information about authentication can be obtained
    from `Authenticating <https://docs.uipath.com/orchestrator/reference/authenticating>`_
    """

    def __init__(self):
        super().__init__()
        pass


class CloudSession(requests.Session):
    """UiPath Cloud extension to :class:`requests.Session`.

    Supports UiPath Automation Cloud refresh token authentication mechanisms for both access and id tokens.
    Performs token refresh automatically and intercepts all :class:`requests.Sessions` verbs, adding the tokens.
    There is only one non-interactive auth flow which requires a refresh token as input.

    Authentication data can be obtained from
    `UiPath Automation Cloud <https://docs.uipath.com/orchestrator/reference/consuming-cloud-api>`_
    """

    def __init__(
            self,
            refresh_token,
            account_logical_name,
            tenant_logical_name,
            client_id,
            base_url
    ):
        """Construct a new authentication client session for Ui.

        :param refresh_token: Refresh token used for authentication. It is named `User Key` in the Cloud web console
        :type refresh_token: str
        :param account_logical_name: Account logical name from UiPath Cloud
        :type account_logical_name: str
        :param tenant_logical_name: Tenant logical name from UiPath Cloud
        :type tenant_logical_name: str
        :param client_id: Client id obtained from UiPath Cloud
        :type client_id: str
        :param base_url: Base url of the UiPath Cloud environment being used. Just the path is expected,
            without scheme, port or fragments
        :type base_url: str
        """
        super().__init__()
        self._logger = logging.getLogger(__name__)

        self._id_token = None
        self._access_token = None
        self._access_token_expiration = None

        assert base_url and isinstance(base_url, str) and base_url in UIPATH_AUTH_URLS
        self._base_url = base_url
        self._access_refresh_url = UIPATH_AUTH_URLS[base_url]  # 'https://account.uipath.com/oauth/token'

        assert refresh_token and isinstance(refresh_token, str)
        self._refresh_token = refresh_token

        assert account_logical_name and isinstance(account_logical_name, str)
        self._account_logical_name = account_logical_name

        assert tenant_logical_name and isinstance(tenant_logical_name, str)
        self._tenant_logical_name = tenant_logical_name

        assert client_id and isinstance(client_id, str)
        self._client_id = client_id

        # maximum retries: 3. only applies to DNS lookups, socket or connection timeout
        # see `Requests Documentation <https://requests.readthedocs.io/en/latest/api/#requests.adapters.BaseAdapter>`_
        adapter = HTTPAdapter(max_retries=3)
        self.mount('https://', adapter=adapter)

    def _refresh_access_token(self):
        """
        Refresh access token using the refresh token (if available)

        :return:
        """

        if not self._refresh_token:
            self._logger.warning('Cannot obtain access token without a refresh token')
            return

        self._logger.info('Refreshing access and id token')

        body = {
            'grant_type': 'refresh_token',
            'client_id': f'{self._client_id}',
            'refresh_token': f'{self._refresh_token}'
        }
        headers = {
            'Content-Type': 'application/json',
            'X-UIPATH-TenantName': f'{self._tenant_logical_name}'
        }
        r = requests.post(f'{self._access_refresh_url}/oauth/token', json=body, headers=headers)
        if r.status_code == 401 and r.json().get('error', None) == 'access_denied':
            self._logger.error("Could not authenticate: 401")
            raise AuthError(401, r.json().get('error', None))
        if r.status_code == 403 and r.json().get('error', None) == 'invalid_grant':
            self._logger.error("Could not authenticate: 403")
            raise AuthError(403, r.json().get('error', None))
        r.raise_for_status()

        token_content = r.json()
        try:
            self._id_token = token_content['id_token']
            self._access_token = token_content['access_token']
            self._access_token_expiration = datetime.utcnow() + timedelta(seconds=int(token_content["expires_in"]))
        except KeyError as exc:
            self._logger.error(f"Token did not contain key {exc}")
            raise UiPathException("Invalid response from auth endpoint")

    def check_and_refresh_access_token(self):
        """
        Checks if access token needs to be refreshed and refreshes if possible

        :return:
        """
        can_refresh = bool(self._refresh_token)
        needs_refresh = self._access_token_expiration and \
                        (datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRATION_BUFFER)) >= \
                        self._access_token_expiration
        needs_token = not self._access_token
        if (needs_refresh or needs_token) and can_refresh:
            self._refresh_access_token()

    def request(self, method, url, data=None, headers=None, **kwargs):
        """
        Intercept all requests and add the auth token if present. Implementation of the base class method

        :param method: method for the new :class:`Request` object.
        :type method: str
        :param url: URL for the new :class:`Request` object.
        :type url: str
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param headers: (optional) Dictionary of HTTP Headers to send with the
            :class:`Request`.
        :rtype: requests.Response
        """


        if self._access_token:
            self._logger.debug(f"Adding token {self._access_token} to request.", self._access_token)
            if not headers:
                headers = dict()
            headers['Authorization'] = f'Bearer {self._access_token}'
            headers['X-UIPATH-TenantName'] = self._tenant_logical_name

        return super().request(method, url, headers=headers, data=data, **kwargs)
