from urllib.parse import urlparse
import logging
# from time import time
import time
import random

from .auth import CloudSession
from .exceptions import BadInputException, ApiError, InternalServerError, AuthError, RateLimitError
from .constants import UIPATH_AUTH_URLS, DEFAULT_NETLOC


class Uipath:

    def __init__(self,
                 base_url=None,
                 client_id=None,
                 account_logical_name=None,
                 tenant_logical_name=None,
                 refresh_token=None,
                 username=None,
                 password=None,
                 tenant=None,
                 max_retries_on_error=4,
                 max_retries_on_rate_limit=4
                 ):
        """
        Base class for making API calls to the Orchestrator. Responsible with communication protocol

        :param base_url: The base url of the Orchestrator. If none is provided, UiPath Cloud will be used by default
        :type base_url: str
        :param client_id: (Optional) the client id, as found in the UiPath Cloud account
        :type client_id: str
        :param account_logical_name: (Optional) the account logical name, inside the UiPath Cloud account
        :type account_logical_name: str
        :param tenant_logical_name: (Optional) the tenant logical name
        :type tenant_logical_name: str
        :param refresh_token: (Optional) the refresh token (seen as User Key) that will be used to obtain access
                to the UiPath Cloud API
        :type refresh_token: str
        :param username: (Optional) username for onprem Orchestrator
        :type username: str
        :param password: (Optional) password for onprem Orchestrator
        :type password: str
        :param tenant: (Optional) tenancy name for onprem Orchestrator
        :type tenant: str
        """
        self.__logger = logging.getLogger(__name__)

        self._max_retries_on_error = max_retries_on_error
        self._max_retries_on_rate_limit = max_retries_on_rate_limit

        if not base_url:
            self.__logger.info(f"Host URL was not provided. Using {DEFAULT_NETLOC} as default")
            # netloc as defined in RFC 1808
            self._netloc = DEFAULT_NETLOC
        else:
            parse_res = urlparse(base_url)
            if parse_res.scheme and parse_res.scheme != 'https':
                raise BadInputException('Scheme needs to be `https`')
            if not parse_res.netloc or parse_res.netloc in UIPATH_AUTH_URLS:
                self._netloc = DEFAULT_NETLOC
            else:
                self._netloc = parse_res.netloc

        if self._netloc in UIPATH_AUTH_URLS:
            if not refresh_token:
                raise BadInputException('Refresh token needs to be set')
            self._refresh_token = refresh_token
            if not account_logical_name:
                raise BadInputException('Account logical name needs to be set')
            self._account_logical_name = account_logical_name
            if not tenant_logical_name:
                raise BadInputException('Tenant logical name needs to be set')
            self._tenant_logical_name = tenant_logical_name
            if not client_id:
                raise BadInputException('Client ID needs to be set')
            self._client_id = client_id

            self._session = CloudSession(
                refresh_token=refresh_token,
                account_logical_name=account_logical_name,
                tenant_logical_name=tenant_logical_name,
                client_id=client_id,
                base_url=base_url
            )

            self._hostname = f'https://{self._netloc}/{self._account_logical_name}/{self._tenant_logical_name}'
        else:
            if not username:
                raise BadInputException('Username needs to be set')
            self._username = username
            if not password:
                raise BadInputException('Password needs to be set')
            self._password = password
            if not tenant:
                raise BadInputException('Tenant name needs to be set')
            self._tenant = tenant
            self._hostname = f'https://{self._netloc}'
        self.__logger = logging.getLogger(__name__)

    def request(self, method, route, data, timeout=None):
        """
        Handle access tokens and make the request

        :param data:
        :type data:
        :param method:
        :type method:
        :param route:
        :type route:
        :param timeout:
        :type timeout:
        :return:
        :rtype:
        """

        try:
            self._session.check_and_refresh_access_token()
        except AuthError as exc:
            self.__logger.error("Could not authenticate")
            self.__logger.error(f'received {exc!r}')
            raise
        except Exception as exc:
            self.__logger.error('There was a problem during authentication')
            self.__logger.error(f'received {exc!r}')
            raise AuthError(error='AuthError', msg=f'{exc!r}')
        return self.request_json_object_with_retry(method, route, data, timeout)

    def request_json_object_with_retry(self,
                                       method,
                                       route,
                                       data,
                                       timeout=None):
        """
        Handle retry logic. Pass parameters to :meth:`request_json_object`.

        :param timeout: (Optional) HTTP method timeout
        :type timeout: int
        :param data: JSON body for the HTTP method
        :type data: dict
        :param method: HTTP method to call
        :type method: str
        :param route: The API route to call, including: path, query and fragments
        :type route: object
        :return: the API call result as a JSON-Serializable object
        """
        attempt = 0
        rate_limit_errors = 0

        while True:
            self.__logger.info(f'Method {method} sent to {route}')
            try:
                return self.request_json_string(method, route, data, timeout=timeout)
            except AuthError as e:
                self.__logger.error(f'Authentication error {e!r}')
                raise
            except InternalServerError as e:
                attempt += 1
                if attempt <= self._max_retries_on_error:
                    # Use exponential back_off
                    back_off = 2 ** attempt * random.random()
                    self.__logger.info(f'{repr(e)} Retrying in {back_off:.2f}')
                    time.sleep(back_off)
                else:
                    raise
            except RateLimitError as e:
                rate_limit_errors += 1
                if self._max_retries_on_rate_limit >= rate_limit_errors:
                    # Set default backoff to 5 seconds.
                    back_off = e.back_off if e.back_off is not None else 5.0
                    self.__logger.info(f'Ratelimit: Retrying in {back_off:.2f} seconds.')
                    time.sleep(back_off)
                else:
                    raise

    def request_json_string(self,
                            method,
                            route,
                            data,
                            timeout=None):
        """
        See :meth:`request_json_string_with_retry` for description of
        parameters.
        """

        headers = dict()
        headers['Content-Type'] = 'application/json'
        if hasattr(self, '_headers'):
            headers.update(self._headers)

        url = f'https://{self._netloc}/{route}'
        r = self._session.request(method, url,
                                  headers=headers,
                                  data=data,
                                  timeout=timeout)

        if r.status_code >= 500:
            raise InternalServerError(r.status_code, r.text)
        elif r.status_code == 400:
            raise ApiError(400, r.text)
        elif r.status_code in (401, 403):
            assert r.headers.get('content-type') == 'application/json', (
                    'Expected content-type to be application/json, got %r' %
                    r.headers.get('content-type'))
            raise AuthError(r.status_code, r.json().get('error', None))
        elif r.status_code == 429:
            if r.headers.get('content-type') == 'application/json' and 'retry-after' in r.headers:
                retry_after = r.headers.get('retry-after')
            else:
                retry_after = None
            raise RateLimitError(r.status_code, retry_after)
        elif 200 <= r.status_code <= 299:
            return r.json()
        raise ApiError(r.status_code, r.text)
