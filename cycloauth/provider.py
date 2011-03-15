import urlparse, time, functools
import cyclone.web
import oauth2
from oauth2 import generate_verifier, Consumer, Error, MissingSignature
from twisted.python import log
from twisted.internet import defer
from cycloauth.utils import (generate_string, get_normalized_parameters,
                                    NOnceList, oauth_request)
from cycloauth.errors import *
from cycloauth.signatures import HMAC_SHA1, PLAINTEXT
from cycloauth.token import Token


def handlers(settings):
  if 'oauth_authorization_handler' in settings:
    m = settings['oauth_authorization_handler']
    authz_mod = __import__('.'.join(m.split('.')[:-1]), globals(), locals(), [], -1)
    for part in m.split('.')[1:]:
      authz_mod = getattr(mod, part)
  else:
    authz_mod =  AuthorizeHandler
  ret = [
    ('/oauth/request_token', RequestTokenHandler),
    ('/oauth/authorize', authz_mod),
    ('/oauth/access_token', AccessTokenHandler)]
  if 'debug' in settings and settings['debug']:
    ret += [
      ('/oauth/register_application', RegisterApplicationHandler)]
  return ret

def async_authenticated(method):
  "same as cyclone.web.authenticated but doesn't redirect just returns 403"
  "and works with asynchronous authentication methods (that might require a db lookup or something)"
  "using this decorator means you do not have to use cyclone.web.asynchronous and return"
  "values will be entirely ignored"
  @functools.wraps(method):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def wrapper(self, *args, **kwargs):
    user = yield defer.maybeDeferred(self.get_current_user())
    if not user:
      raise cyclone.web.HTTPError(403)
    method(self, *args, **kwargs)
  return wrapper


class OAuthApplicationMixin(object):
  oauth_signature_methods = {
    'HMAC-SHA1': HMAC_SHA1,
    'PLAINTEXT': PLAINTEXT
  }
  
  @property
  def oauth_nonce_list(self):
    if getattr(self, '_nonce_list', None) is None:
      nonce_cache_size = self.settings.get('nonce_cache_size', 20000)
      self._nonce_list = NOnceList(nonce_cache_size)
    return self._nonce_list
  
  @property
  def oauth_storage(self):
    if getattr(self, '_oauth_storage', None) is None:
      factory_name = self.settings.get('oauth_storage_factory', 'mirror.web.oauth.storage.BaseStorage')
      fn = '.'.join(factory_name.split('.')[:-1])
      mod = __import__(fn, globals(), locals(), [], -1)
      for part in factory_name.split('.')[1:]:
        mod = getattr(mod, part)
      self._oauth_storage = mod(self.settings)
    return self._oauth_storage
  

class OAuthRequestHandlerMixin(object):
  def get_error_html(self, status_code, **kwargs):
    e = kwargs.get('exception')
    if isinstance(e, Error):
      return """
      <html>
        <head><title>%(title)s</title>
        </head>
        <body><h1>OAuth Error</h1><p>%(title)s</p></body>
      </html>
      """ % {'title': e.log_message}
    else:
      return cyclone.web.RequestHandler.get_error_html(self, status_code, **kwargs)
  
  @defer.inlineCallbacks
  def get_current_user(self):
    if self.oauth_consumer and self.oauth_token:
      defer.returenValue(self.oauth_token)
    consumer = yield self.application.oauth_storage.get_consumer(self.oauth_params['oauth_consumer_key'])
    token = yield self.application.oauth_storage.get_access_token(self.oauth_params['oauth_token'])
    try:
      self._check_signature(consumer, token)
      self.oauth_consumer = consumer
      self.oauth_token = token
      defer.returnValue(self.oauth_token)
    except:
      log.err()
      self.oauth_consumer = None
      self.oauth_token = None
      defer.returnValue(None)
  
  @property
  def oauth_consumer(self):
    consumer_key = self.oauth_params.get('oauth_consumer_key', None)
    oauth_token_key = request.oauth_params.get('oauth_token', None)
    if len(self.oauth_params) == 0:
      raise NotAnOAuthRequest('The request made does not contain one or more OAuth parameters.')
    elif not (consumer_key or oauth_token_key):
      raise PartialOAuthRequest('A consumer or token was not provided in the request.')
    consumer = self.application.storage[consumer_key]
    token = self.application.oauth_storage[token]
    self._check_signature(consumer, token)
    return consumer
  
  def _check_signature(self, consumer, token):
    try:
      nonce = self.oauth_params['oauth_nonce']
    except KeyError:
      raise PartialOAuthRequest('Missing oauth_nonce.')
    self._check_nonce(nonce)
    try:
      timestamp = self.oauth_params['oauth_timestamp']
    except KeyError:
      raise PartialOAuthRequest('Missing oauth_timestamp.')
    self._check_timestamp(timestamp)
    try:
      signature_method = self.application.oauth_signature_methods[self.oauth_params['oauth_signature_method']]()
    except KeyError:
      raise UnknownSignature('Unknown oauth_signature_method.')
    oauth_req = oauth_request(self.request)
    try:
      signature = self.oauth_params['oauth_signature']
    except KeyError:
      raise MissingSignature('The oauth_signature is missing')
    valid = signature_method.check(oauth_req, consumer, token, signature)
    if not valid:
      key, base = signature_method.signing_base(oauth_req, consumer, token)
      raise Error(('Invalid signature. Expected signature base string: ' + str(base)), 'sock')
  
  def _check_timestamp(self, timestamp, threshold=300):
    if timestamp is None:
      raise Error("The oauth_timestamp parameter is missing.")
    timestamp = int(timestamp)
    now = int(time.time())
    lapsed = now - timestamp
    if lapsed > threshold:
      raise Error('Expired timestamp: given %d and now %s has a greater difference than the threshold %d' % (
        timestamp, now, threshold
      ))
  
  def _check_nonce(self, nonce):
    if nonce in self.application.oauth_nonce_list:
      raise NOnceReplayed('The provided nonce value has been used recently.')
    self.application.oauth_nonce_list.append(nonce)
      

  def _checks_positive_for_oauth(self, params_var):
    return True in [p.find('oauth_') >= 0 for p in params_var]
  
  @property
  def oauth_header(self):
    extracted = {}
    try:
      auth_header = self.request.headers['authorization']
      if auth_header[:6] == 'OAuth ':
        auth_header = auth_header.lstrip('OAuth ')
        try:
          extracted = oauth2.Request._split_header(auth_header)
        except Exception, e:
          log.err()
          raise Error('Unable to parse OAuth parameters from the Authorization Header.')
    except KeyError:
      pass
    return extracted
  
  @property
  def oauth_arguments(self):
    extracted = {}
    if self._checks_positive_for_oauth(self.request.arguments):
      extracted = dict((k, v) for k, v in self.request.arguments.iteritems() if k.find('oauth_') >= 0)
    return extracted
  
  @property
  def oauth_params(self):
    if getattr(self, '_oauth_params', None) is None:
      extracted = {}
      extracted.update(self.oauth_header)
      extracted.update(self.oauth_arguments)
      self._oauth_params = dict((k, extracted[k][0]) for k in extracted.iterkeys())
    return self._oauth_params
  
  @property
  def nonoauth_argument(self):
    oauth_param_keys = self.oauth_params.keys()
    return dict([k, v] for k, v in self.params.iteritems() if k not in oauth_param_keys)


class RegisterApplicationHandler(cyclone.web.RequestHandler, OAuthRequestHandlerMixin):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def get(self):
    c = yield self.application.oauth_storage.add_consumer()
    c.key = 'omgnowai'
    c.secret = 'omgyeswai'
    yield self.application.oauth_storage.save_consumer(c)
    self.write(dict(
      key=c.key,
      secret=c.secret
    ))
    self.finish()


class RequestTokenHandler(cyclone.web.RequestHandler, OAuthRequestHandlerMixin):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def get(self):
    consumer = yield self.application.oauth_storage.get_consumer(self.oauth_params['oauth_consumer_key'])
    self._check_signature(consumer, None)
    token = yield self.application.oauth_storage.add_request_token()
    callback = self.oauth_params.get('oauth_callback', None)
    if callback:
      if 'callback' == 'oob':
        if hasattr(consumer, 'callback'):
          token.set_callback(consumer.callback)
        else:
          raise PartialOAuthRequest("There is no callback set for out-of-band (oob) use")
      else:
        token.set_callback(callback)
    else:
      if hasattr(consumer, 'callback'):
        token.set_callback(consumer.callback)
      else:
        raise PartialOAuthRequest("Missing oauth_callback. Required by OAuth 1.0a")
    yield self.application.oauth_storage.save_request_token(token)
    self.set_header('Content-Type', 'text/plain')
    self.write(token.to_string())
    self.finish()


class AuthorizeHandler(cyclone.web.RequestHandler, OAuthRequestHandlerMixin):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def get(self):
    token = yield self.application.oauth_storage.get_request_token(self.oauth_params['oauth_token'])
    token.set_verifier()
    yield self.application.oauth_storage.save_request_token(token)
    cb = token.get_callback_url()
    self.redirect(cb)


class AccessTokenHandler(cyclone.web.RequestHandler, OAuthRequestHandlerMixin):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def get(self):
    consumer = yield self.application.oauth_storage.get_consumer(self.oauth_params['oauth_consumer_key'])
    request_token = yield self.application.oauth_storage.get_request_token(self.oauth_params['oauth_token'])
    try:
      verifier = self.oauth_params['oauth_verifier']
    except KeyError:
      raise InvalidVerifier('Missing oauth_verifier. Required by OAuth 1.0a')
    self._check_signature(consumer, request_token)
    if verifier != request_token.verifier:
      raise InvalidVerifier('Invalid Verifier.')
    access_token = yield self.application.oauth_storage.add_access_token()
    yield self.application.oauth_storage.save_access_token(access_token)
    self.set_header('Content-Type', 'text/plain')
    self.write(access_token.to_string())
    self.finish()
