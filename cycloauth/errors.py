from oauth2 import Error as OAuthError
from cyclone.web import HTTPError


class Error(HTTPError):
  def __init__(self, msg, *args):
    self.status_code = 500
    self.log_message = msg
    self.args = args
  
  def __str__(self):
    return 'HTTP ERROR: ' + str(self.status_code) + ' ' + \
            self.log_message + ' ' + str(self.args)


class NotAnOAuthRequest(Error):
  """Happens when a request has been found not to be OAuth like."""


class PartialOAuthRequest(Error):
  """There are some oauth parameters present in the request, but one or more is are missing."""


class UnknownSignature(Error):
  """Error indicating that an unknown signing method was used on the request."""


class NOnceReplayed(Error):
  """Error signals that the n-once value has already been used within a certain threshold."""


class InvalidVerifier(Error):
  """Error signalling that the verifier provided is invalid, because it either does not match or was not provided."""