'''
    This will handle the token retrieval. It offers two options, EGA and Passports
'''
import logging
import sys
import time
import platform

from collections import namedtuple
#import traceback
from os import chmod, stat
from configparser import ConfigParser, MissingSectionHeaderError
import requests
import qrcode

USERINFO_ENDPOINT = 'https://login.elixir-czech.org/oidc/userinfo'

class AuthClientEGA:
    '''
       It will use the credentials provided (username/password) to authenticate to EGA
       and obtain a token
    '''
    _token = None
    credentials = None
    token_expires_at = None
    token_expiry_seconds = 1 * 60 * 60  # token expires after 1 hour

    def __init__(self, url, client_secret, standard_headers):
        self.url = url
        self.client_secret = client_secret
        self.standard_headers = standard_headers

    @property
    def token(self):
        '''
            Start remote authentication workflow using EGA accounts
        '''
        if self._token is None or time.time() >= self.token_expires_at:

            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            headers.update(self.standard_headers)

            data = {"grant_type": "password",
                    "client_id": "f20cd2d3-682a-4568-a53e-4262ef54c8f4",
                    "scope": "openid",
                    "client_secret": self.client_secret,
                    "username": self.credentials.username,
                    "password": self.credentials.password
                    }

            try:
                req = requests.post(self.url, headers=headers, data=data)
                logging.info('')
                reply = req.json()
                req.raise_for_status()
                oauth_token = reply['access_token']
                logging.info("Authentication success for user '%s'", self.credentials.username)
            except ConnectionError:
                logging.exception("""
                Could not connect to the authentication service at %s.
                Check that the necessary outbound ports are open in your firewall.
                See the documentation for more information.""", self.url)
                sys.exit()
            except Exception:
                logging.exception(
                    "Invalid username, password or secret key - please check and retry."
                    " If problem persists contact helpdesk on helpdesk@ega-archive.org")
                sys.exit()

            self._token = oauth_token
            self.token_expires_at = time.time() + self.token_expiry_seconds

        return self._token

class AuthClientPassport:
    '''
        This will handle the token retrieval. If a new token will be needed, a QR code and an URL
        will be shown. The user must scan the code or follow the URL, and authenticate. The TOKEN
        will be then retrieved by the client.
    '''
    _token = None
    credentials = None
    grant_type = 'urn:ietf:params:oauth:grant-type:device_code'

    def __init__(self,
                 authentication_parameters_file="auth.cfg",
                 access_token="access_token.txt"):
        self.authentication_parameters_file = authentication_parameters_file
        self.access_token = access_token

    @property
    def token(self):
        """Start remote authentication workflow."""

        # check if we have a valid token
        self._token = self.load_token()
        # None or token
        if self._token:
            return self._token

        logging.debug("\n * Requesting token")

        self.credentials = self.get_auth_credentials()
        self.remote_auth_instructions()

        token_response = self.poll_for_token()

        if 'expires_in' in token_response:
            logging.debug("Expires in: %s seconds", token_response['expires_in'])

        if 'access_token' in token_response:

            if logging.DEBUG >= logging.root.level:
                logging.debug('Access Token: %s', token_response.get("access_token"))
                userinfo = make_userinfo_request(token_response)
                logging.debug("User info: ")
                for key, val in userinfo.items():
                    logging.debug("%s=>%s", key, val)

            self._token = token_response.get("access_token")
            self.save_token()
            #return token_response.get("access_token")
            return self._token

        logging.debug('Error: Authentication response did not contain an access token.')
        return self._token

    def parse_authentication_config_file(self):
        '''
            Gets the configuration file path, and returns the parsed configuration
        '''
        try:
            config = ConfigParser()
            config.read(self.authentication_parameters_file)
            config_vars = {
                'client_id' : config.get('authentication', 'client_id'),
                'client_s' : config.get('authentication', 'client_secret'),
                'url_auth' : config.get('authentication', 'url_auth'),
                'url_token' : config.get('authentication', 'url_token'),
                'scope' : config.get('authentication', 'scope')
            }
        except MissingSectionHeaderError as missing_err:
            logging.error("ERROR (MissingSectionHeaderError): %s", missing_err)
            sys.exit(2)
        return namedtuple("Config", config_vars.keys())(*config_vars.values())

    def get_auth_credentials(self):
        '''
            Makes the request to authentication server and retrieve remote authentication
            credentials.
        '''

        config = self.parse_authentication_config_file()

        client_id = config.client_id
        client_s = config.client_s
        url_auth = config.url_auth

        # Make a request to authentication server
        response = requests.post(url_auth,
                                 auth=(client_id, client_s),
                                 data={'client_id': client_id,
                                       'scope': config.scope})
        #config.claims})
        if 'error' in response.json():
            logging.error("ERROR in response (%s):\n    %s", url_auth, response.json())
            logging.debug("""
        auth = (client_id: %s,
                client_s: %s),
        data = {'client_id': %s,
                'scope': %s}
    """, client_id, client_s, client_id, config.scope)
            sys.exit(5)
        return response.json()

    def poll_for_token(self):
        '''
            This will query every second for the token. Meanwhile the user
            is authenticating using the external device
        '''
        try:
            device_code = str(self.credentials['device_code'])
        except KeyError as kerr:
            logging.error("ERROR KeyError: %s", kerr)
            return ""

        timeout = 120
        interval = 1

        config = self.parse_authentication_config_file()
        client_id = config.client_id
        client_s = config.client_s
        url_token = config.url_token
        while True:
            time.sleep(interval)
            timeout -= interval

            # Request token from authentication server
            token_response = requests.post(url_token,
                                           auth=(client_id, client_s),
                                           data={'grant_type': self.grant_type,
                                                 'device_code': device_code,
                                                 'client_id': client_id,
                                                 'scope': config.scope
                                                })

            if 'error' in token_response.json():
                if token_response.json()['error'] == 'authorization_pending':
                    # User hasn't authenticated yet, wait for some time
                    pass
                elif token_response.json()['error'] in ['slow_down', 'buffering']:
                    # We are pinging auth server too much, ping more seldom
                    interval += 1
                    #pass
                else:
                    logging.error("Error(%s): %s", token_response.json()["error"],
                                  token_response.json()["error_description"])
                    logging.error('Authentication was terminated.')
                    break
            else:
                break

            if timeout < 0:
                logging.error('''
        Authentication timed out, please try again.
        Error(%s): %s.
        Authentication was terminated.''', token_response.json()["error"],
                              token_response.json()["error_description"])
                break

        return token_response.json()


    def remote_auth_instructions(self):
        """Print remote authentication instructions for user."""
        url = ""
        # Extract remote authentication address, or construct it if complete uri is not available
        if 'verification_uri_complete' in self.credentials:
            url = self.credentials['verification_uri_complete']
        elif 'verification_uri' and 'user_code' in self.credentials:
            url = f'{self.credentials["verification_uri"]}?user_code={self.credentials["user_code"]}'
        else:
            logging.error('''
            Authentication server response did not contain required items.
            Credentials that were returned:
            %s''', self.credentials)
            sys.exit(1)

        # Print remote authentication instructions
        logging.info("""
    Please authenticate with another device, for example your phone or computer, to gain access to
    permitted datasets. If you cannot read the QR code with a smartphone, you may use the link below:
        URL: %s
        """, url)
        print(draw_qr_code(url))

    def save_token(self):
        '''
            Saves the given token in the file access_token.txt
        '''
        with open(self.access_token, 'w+') as token_file:
            token_file.write(self._token)
        chmod(self.access_token, 0o600)
        logging.info("The Access Token is saved into access_token.txt file.")

    def load_token(self):
        """Save access token to file."""

        logging.debug(' * Looking for saved access tokens.')

        try:
            file_age = stat(self.access_token).st_mtime
            # for this service 6 h
            if time.time() - file_age < 21600:
                # Stored access token file is less than one hour old, load the token
                with open(self.access_token, 'r') as token_file:
                    logging.debug('Found a saved access token. Skipping authentication.')
                    return token_file.read()
            else:
            # EGA Data API doesn't allow tokens that are older than one hour
                logging.debug('Found an old access token. Proceed with authentication.')
                return None
        except FileNotFoundError as err:
            logging.debug("No fresh access tokens found, proceed with authentication. %s", err)
            return None

def draw_qr_code(url):
    """Draw QR code."""

    # Determine user operating system
    if platform.system() == "Windows":
        white_block = '▇'
        black_block = '  '
        new_line = '\n'
    else:
        white_block = '\033[0;37;47m  '
        black_block = '\033[0;37;40m  '
        new_line = '\033[0m\n'

    qr_code = qrcode.QRCode()
    qr_code.add_data(url)
    qr_code.make()

    # Draw top white border
    output = white_block*(qr_code.modules_count+2) + new_line

    # Fill QR code area
    for m_line in qr_code.modules:
        output += white_block
        for m_block in m_line:
            if m_block:
                output += black_block
            else:
                output += white_block
        output += white_block + new_line

    # Draw bottom white border
    output += white_block*(qr_code.modules_count+2) + new_line

    return output


def make_userinfo_request(token_resp):
    '''
        Request user's information
    '''

    userinfo_response = requests.post(USERINFO_ENDPOINT,
                                      data={},
                                      headers={
                                          'Authorization': 'Bearer %s' % token_resp['access_token']
                                      })

    if 'error' in userinfo_response.json():
        logging.error("ERROR")
        logging.error(userinfo_response.json()['error'])
        logging.error(userinfo_response.json()['error_description'])

    return userinfo_response.json()
