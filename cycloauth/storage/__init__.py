from collections import namedtuple
from twisted.internet import defer
from zope.interface import Interface, Attribute, implements
from cycloauth.utils import generate_string
from cycloauth.token import Token as OAuthToken
from cycloauth.consumer import Consumer as OAuthConsumer


class IStorage(Interface):
  "A storage mechanism for consumerse, request tokens and access tokens"

  def add_consumer(self, key=None, secret=None, **kwargs):
    "creates a consumer in the store"
  
  def save_consumer(self, consumer):
    "saves a consumer to the store"
  
  def remove_consumer(self, key, **kwargs):
    "removes a consumer in the store"
  
  def get_consumer(self, key, **kwargs):
    "gets a consumer from the store"

  def add_request_token(self, key=None, secret=None, **kwargs):
    "adds a request token to the store"
  
  def save_request_token(self, token):
    "saves a request token to the store"
  
  def remove_request_token(self, key):
    "removes a request token from the store"
  
  def get_request_token(self, key):
    "retrieves a request token from the store"

  def add_access_token(self, key=None, secret=None, **kwargs):
    "adds an access token to the store"
  
  def save_request_token(self, token):
    "saves a request token to the store"

  def remove_access_token(self, key):
    "removes an access token from the store"
  
  def get_access_token(self, key):
    "retrieves an access token from the store"
  
  request_token_factory = Attribute("")
  access_token_factory = Attribute("")
  consumer_factory = Attribute("")
  

class IToken(Interface):
  key = Attribute("")
  secret = Attribute("")
  callback = Attribute("")
  callback_confurmed = Attribute("")
  verifier = Attribute("")
  

class IConsumer(Interface):
  callback = Attribute("")
  key = Attribute("")
  secret = Attribute("")


class BaseConsumer(OAuthConsumer):
  implements(IConsumer)


class BaseToken(OAuthToken):
  implements(IToken)


@defer.inlineCallbacks
def key_secret_generator(storage, func, key, secret):
  if key is None:
    while True:
      key = generate_string()
      if not (yield getattr(storage, func)(key)):
        break
  if secret is None:
    secret = generate_string(128)
  defer.returnValue(dict(key=key, secret=secret))


class BaseStorage(object):
  "implements an in-memory Storage as a singleton"
  implements(IStorage)
  
  request_token_factory = BaseToken
  access_token_factory = BaseToken
  consumer_factory = BaseConsumer
  
  def __init__(self, settings):
    self.consumers = {}
    self.request_tokens = {}
    self.access_tokens = {}
  
  @defer.inlineCallbacks
  def add_consumer(self, key=None, secret=None, **kwargs):
    ks = yield key_secret_generator(self, 'get_consumer', key, secret)
    ret = yield self.save_consumer(self.consumer_factory(key=ks['key'], secret=ks['secret'], **kwargs))
    defer.returnValue(ret)
  
  def save_consumer(self, consumer):
    self.consumers[consumer.key] = consumer
    return defer.succeed(consumer)
  
  def get_consumer(self, key):
    ret = self.consumers.get(key, None)
    return defer.succeed(ret)
  
  def remove_consumer(self, key):
    if key in self.consumers:
      del self.consumers[key]
    return defer.succeed(True)
  
  @defer.inlineCallbacks
  def add_request_token(self, key=None, secret=None, **kwargs):
    ks = yield key_secret_generator(self, 'get_request_token', key, secret)
    ret = yield self.save_request_token(self.request_token_factory(key=ks['key'], secret=ks['secret'], **kwargs))
    defer.returnValue(ret)
  
  def save_request_token(self, token):
    self.request_tokens[token.key] = token
    return defer.succeed(token)
  
  def get_request_token(self, key):
    ret = self.request_tokens.get(key, None)
    return defer.succeed(ret)
  
  def remove_request_token(self, key):
    if key in self.request_tokens:
      del self.request_tokens[key]
    return defer.succeed(True)

  @defer.inlineCallbacks
  def add_access_token(self, key=None, secret=None, **kwargs):
    ks = yield key_secret_generator(self, 'get_access_token', key, secret)
    ret = yield self.save_access_token(self.access_token_factory(key=ks['key'], secret=ks['secret'], **kwargs))
    defer.returnValue(ret)
  
  def save_access_token(self, token):
    self.access_tokens[token.key] = token
    return defer.succeed(token)
  
  def get_access_token(self, key):
    ret = self.access_tokens.get(key, None)
    return defer.succeed(ret)
  
  def remove_access_token(self, key):
    if key in self.access_tokens:
      del self.access_tokens[key]
    return defer.succeed(True)
