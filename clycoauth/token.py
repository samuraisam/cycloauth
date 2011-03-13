import urlparse
from twisted.internet import defer
from oauth2 import Token as OAuthToken
from cycloauth.utils import generate_string

class Token(OAuthToken):
  def __init__(self, key, secret, callback=None, verifier=None, **kwargs):
    self.key = key
    self.secret = secret
    self.verifier_generator = kwargs.get('verifier_generator', lambda: generate_string(32))

    if self.key is None or self.secret is None:
      raise ValueError("Key and secret must be set.")
    if callback is not None:
      self.set_callback(callback)
    if verifier is not None:
      self.set_verifier(verifier)

  def set_verifier(self, verifier=None):
    if verifier is not None:
      self.verifier = verifier
    else:
      self.verifier = self.verifier_generator()

  def get_callback_url(self):
    if self.callback and self.verifier:
      # Append the oauth_verifier.
      parts = urlparse.urlparse(self.callback)
      scheme, netloc, path, params, query, fragment = parts[:6]
      if query:
        query = "%s&oauth_token=%s&oauth_verifier=%s" % (query, self.key, self.verifier)
      else:
        query = "oauth_token=%s&oauth_verifier=%s" % (self.key, self.verifier)
      return urlparse.urlunparse((scheme, netloc, path, params, query, fragment))
    return self.callback
