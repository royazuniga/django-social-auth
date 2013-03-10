"""
Linkedin OAuth/OAuth2 support

No extra configurations are needed to make this work.
"""
from xml.etree import ElementTree
from xml.parsers.expat import ExpatError
from urllib import urlencode, urlopen

from oauth2 import Token
from django.utils import simplejson

from social_auth.utils import setting
from social_auth.backends import (
    ConsumerBasedOAuth,
    BaseOAuth2,
    OAuthBackend,
)
from social_auth.exceptions import AuthCanceled, AuthUnknownError

#OAUTH
LINKEDIN_SERVER = 'linkedin.com'
LINKEDIN_REQUEST_TOKEN_URL = 'https://api.%s/uas/oauth/requestToken' % \
                             LINKEDIN_SERVER
LINKEDIN_ACCESS_TOKEN_URL = 'https://api.%s/uas/oauth/accessToken' % \
                            LINKEDIN_SERVER
LINKEDIN_AUTHORIZATION_URL = 'https://www.%s/uas/oauth/authenticate' % \
                             LINKEDIN_SERVER
LINKEDIN_CHECK_AUTH = 'https://api.%s/v1/people/~' % LINKEDIN_SERVER
# Check doc at http://developer.linkedin.com/docs/DOC-1014 about how to use
# fields selectors to retrieve extra user data
LINKEDIN_FIELD_SELECTORS = ['id', 'first-name', 'last-name']

# OAUTH2
LINKEDIN2_AUTHORIZATION_URL = 'https://www.linkedin.com/uas/oauth2/authorization'
LINKEDIN2_ACCESS_TOKEN_URL = 'https://www.linkedin.com/uas/oauth2/accessToken'
LINKEDIN2_USER_DATA_URL = 'https://api.linkedin.com/v1/people/~'
LINKEDIN2_SERVER = 'api.linkedin.com'


class LinkedinBackend(OAuthBackend):
    """Linkedin OAuth authentication backend"""
    name = 'linkedin'
    EXTRA_DATA = [('id', 'id'),
                  ('first-name', 'first_name'),
                  ('last-name', 'last_name')]

    def get_user_details(self, response):
        """Return user details from Linkedin account"""
        first_name, last_name = response['first-name'], response['last-name']
        email = response.get('email-address', '')
        return {'username': first_name + last_name,
                'fullname': first_name + ' ' + last_name,
                'first_name': first_name,
                'last_name': last_name,
                'email': email}


class LinkedinAuth(ConsumerBasedOAuth):
    """Linkedin OAuth authentication mechanism"""
    AUTHORIZATION_URL = LINKEDIN_AUTHORIZATION_URL
    REQUEST_TOKEN_URL = LINKEDIN_REQUEST_TOKEN_URL
    ACCESS_TOKEN_URL = LINKEDIN_ACCESS_TOKEN_URL
    AUTH_BACKEND = LinkedinBackend
    SETTINGS_KEY_NAME = 'LINKEDIN_CONSUMER_KEY'
    SETTINGS_SECRET_NAME = 'LINKEDIN_CONSUMER_SECRET'
    SCOPE_VAR_NAME = 'LINKEDIN_SCOPE'
    SCOPE_SEPARATOR = '+'

    def user_data(self, access_token, *args, **kwargs):
        """Return user data provided"""
        fields_selectors = LINKEDIN_FIELD_SELECTORS + \
                           setting('LINKEDIN_EXTRA_FIELD_SELECTORS', [])
        # use set() over fields_selectors since LinkedIn fails when values are
        # duplicated
        url = LINKEDIN_CHECK_AUTH + ':(%s)' % ','.join(set(fields_selectors))
        request = self.oauth_request(access_token, url)
        raw_xml = self.fetch_response(request)
        try:
            return to_dict(ElementTree.fromstring(raw_xml))
        except (ExpatError, KeyError, IndexError):
            return None

    def auth_complete(self, *args, **kwargs):
        """Complete auth process. Check LinkedIn error response."""
        oauth_problem = self.request.GET.get('oauth_problem')
        if oauth_problem:
            if oauth_problem == 'user_refused':
                raise AuthCanceled(self, '')
            else:
                raise AuthUnknownError(self, 'LinkedIn error was %s' %
                                                    oauth_problem)
        return super(LinkedinAuth, self).auth_complete(*args, **kwargs)

    def get_scope(self):
        """Return list with needed access scope"""
        scope = []
        if self.SCOPE_VAR_NAME:
            scope = setting(self.SCOPE_VAR_NAME, [])
        else:
            scope = []
        return scope

    def unauthorized_token(self):
        """Makes first request to oauth. Returns an unauthorized Token."""
        request_token_url = self.REQUEST_TOKEN_URL
        scope = self.get_scope()
        if scope:
            qs = 'scope=' + self.SCOPE_SEPARATOR.join(scope)
            request_token_url = request_token_url + '?' + qs

        request = self.oauth_request(
            token=None,
            url=request_token_url,
            extra_params=self.request_token_extra_arguments()
        )
        response = self.fetch_response(request)
        return Token.from_string(response)


def to_dict(xml):
    """Convert XML structure to dict recursively, repeated keys entries
    are returned as in list containers."""
    children = xml.getchildren()
    if not children:
        return xml.text
    else:
        out = {}
        for node in xml.getchildren():
            if node.tag in out:
                if not isinstance(out[node.tag], list):
                    out[node.tag] = [out[node.tag]]
                out[node.tag].append(to_dict(node))
            else:
                out[node.tag] = to_dict(node)
        return out


class Linkedin2Backend(OAuthBackend):
    """Linkedin2 OAuth authentication backend"""
    name = 'linkedin-oauth2'
    # Default extra data to store
    EXTRA_DATA = [
        ('id', 'id'),
        ('expires', setting('SOCIAL_AUTH_EXPIRATION', 'expires'))
    ]

    def get_user_id(self, details, response):
        print "get_user_id", details, response
        return

    def get_user_details(self, response):
        """Return user details from Linkedin2 account"""
        print response
        return {'username': response.get('login'),
                'email': response.get('email') or '',
                'first_name': response.get('name')}

    @classmethod
    def enabled(cls):
        return True


class Linkedin2Auth(BaseOAuth2):
    """Linkedin2 OAuth2 mechanism"""
    AUTHORIZATION_URL = LINKEDIN2_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = LINKEDIN2_ACCESS_TOKEN_URL
    SERVER_URL = LINKEDIN2_SERVER
    AUTH_BACKEND = Linkedin2Backend
    SETTINGS_KEY_NAME = 'LINKEDIN2_API_KEY'
    SETTINGS_SECRET_NAME = 'LINKEDIN2_API_SECRET'
    SCOPE_SEPARATOR = ','

    def get_scope(self):
        """Return list with needed access scope"""
        return setting('LINKEDIN2_EXTENDED_PERMISSIONS', [])

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = LINKEDIN2_USER_DATA_URL + '?' + urlencode({
            'oauth2_access_token': access_token
        })
        try:
            return simplejson.load(urlopen(url))
        except ValueError:
            return None


# Backend definition
BACKENDS = {
    'linkedin': LinkedinAuth,
    'linkedin-oauth2': Linkedin2Auth,
}
