from cycloauth.storage import BaseStorage, BaseToken, BaseConsumer, key_secret_generator
from txmongo import MongoConnectionPool
from cyclone.web import HTTPError
from twisted.internet import defer


class MongoToken(BaseToken):
  m_id = None
  
  def to_dict(self):
    ret = {
      'key': self.key,
      'secret': self.secret,
      'callback': self.__dict__.get('callback', None),
      'callback_confirmed': self.__dict__.get('callback_confirmed', False),
      'verifier': self.__dict__.get('verifier', None)
    }
    if self.m_id:
      ret['_id'] = self.m_id
    return ret
  
  @classmethod
  def from_dict(cls, d):
    if not d: return None
    ret = cls(key=d['key'], secret=d['secret'])
    if d.get('callback', None):
      ret.set_callback(d['callback'])
    ret.m_id = d.get('_id', None)
    if d.get('verifier', None):
      ret.set_verifier(d['verifier'])
    return ret


class MongoConsumer(BaseConsumer):
  m_id = None
  
  def to_dict(self):
    ret = {
      'key': self.key,
      'secret': self.secret,
      'callback': self.callback
    }
    if self.m_id:
      ret['_id'] = self.m_id
    return ret
  
  @classmethod
  def from_dict(cls, d):
    if not d: return None
    ret = cls(key=d['key'], secret=d['secret'])
    ret.callback = d.get('callback', None)
    ret.m_id = d.get('_id', None)
    return ret


class MongoDBStorage(BaseStorage):
  "implements an storage mechanism for MongoDB"
  
  request_token_factory = MongoToken
  access_token_factory = MongoToken
  consumer_factory = MongoConsumer
  
  def __init__(self, settings):
    self.settings = settings
    self.access_token_collection = settings.get('oauth_access_token_collection', 'oauth_access_tokens')
    self.consumer_collection = settings.get('oauth_consumer_collection', 'oauth_consumers')
    self.request_token_collection = settings.get('oauth_request_token_collection', 'oauth_requets_tokens')
    self.ensured_indexes = {}
  
  @defer.inlineCallbacks
  def add_consumer(self, key=None, secret=None, **kwargs):
    yield self.mongo_ensure(self.consumer_collection, {'key': 1})
    ks = yield key_secret_generator(self, 'get_consumer', key, secret)
    ret = yield self.save_consumer(self.consumer_factory(key=ks['key'], secret=ks['secret'], **kwargs))
    defer.returnValue(ret)
  
  @defer.inlineCallbacks
  def save_consumer(self, consumer):
    yield self.mongo_ensure(self.consumer_collection, {'key': 1})
    r = consumer.to_dict()
    yield self.mongo_save(self.consumer_collection, r)
    defer.returnValue(MongoConsumer.from_dict(r))
  
  @defer.inlineCallbacks
  def get_consumer(self, key):
    yield self.mongo_ensure(self.consumer_collection, {'key': 1})
    r = yield self.mongo_find_one_or_none(self.consumer_collection, {'key': key})
    defer.returnValue(MongoConsumer.from_dict(r) if r else None)
  
  @defer.inlineCallbacks
  def remove_consumer(self, key):
    yield self.mongo_ensure(self.consumer_collection, {'key': 1})
    yield self.mongo_remove(self.consumer_collection, {'key': key})
    defer.returnValue(True)
  
  @defer.inlineCallbacks
  def add_request_token(self, key=None, secret=None, **kwargs):
    self.mongo_ensure(self.request_token_collection, {'key': 1})
    ks = yield key_secret_generator(self, 'get_request_token', key, secret)
    ret = yield self.save_request_token(self.request_token_factory(key=ks['key'], secret=ks['secret'], **kwargs))
    defer.returnValue(ret)
  
  @defer.inlineCallbacks
  def save_request_token(self, token):
    yield self.mongo_ensure(self.request_token_collection, {'key': 1})
    r = token.to_dict()
    yield self.mongo_save(self.request_token_collection, r)
    defer.returnValue(MongoToken.from_dict(r) if r else None)
  
  @defer.inlineCallbacks
  def get_request_token(self, key):
    yield self.mongo_ensure(self.request_token_collection, {'key': 1})
    r = yield self.mongo_find_one_or_none(self.request_token_collection, {'key': key})
    defer.returnValue(MongoToken.from_dict(r))
  
  @defer.inlineCallbacks
  def remove_request_token(self, key):
    yield self.mongo_ensure(self.request_token_collection, {'key': 1})
    yield self.mongo_remove(self.request_token_collection, {'key': key})
    defer.returnValue(True)

  @defer.inlineCallbacks
  def add_access_token(self, key=None, secret=None, **kwargs):
    self.mongo_ensure(self.access_token_collection, {'key': 1})
    ks = yield key_secret_generator(self, 'get_access_token', key, secret)
    ret = yield self.save_access_token(self.access_token_factory(key=ks['key'], secret=ks['secret'], **kwargs))
    defer.returnValue(ret)
  
  @defer.inlineCallbacks
  def save_access_token(self, token):    
    yield self.mongo_ensure(self.access_token_collection, {'key': 1})
    r = token.to_dict()
    yield self.mongo_save(self.request_token_collection, r)
    defer.returnValue(MongoToken.from_dict(r))
  
  @defer.inlineCallbacks
  def get_access_token(self, key):
    yield self.mongo_ensure(self.access_token_collection, {'key': 1})
    r = yield self.mongo_find_one_or_none(self.access_token_collection, {'key': key})
    defer.returnValue(MongoToken.from_dict(r) if r else None)
  
  @defer.inlineCallbacks
  def remove_access_token(self, key):
    yield self.mongo_ensure(self.access_token_collection, {'key': 1})
    yield self.mong_remove(self.access_token_collection, {'key': key})
    defer.returnValue(True)
  
  @property
  @defer.inlineCallbacks
  def db(self):
    if not getattr(self, '_db', None):
      pool = yield self.pool
      self._db = getattr(pool, self.settings.get('oauth_mongo_database', 'oauth'))
    defer.returnValue(self._db)

  @property
  @defer.inlineCallbacks
  def pool(self):
    if not getattr(self, '_pool', None):
      mongo = yield MongoConnectionPool(
        host=self.settings.get('oauth_mongo_host', '127.0.0.1'), 
        port=self.settings.get('oauth_mongo_port', 27017),
        reconnect=self.settings.get('oauth_mongo_reconnect', True), 
        pool_size=self.settings.get('oauth_mongo_pool_size', 5))
      self._pool = mongo
    defer.returnValue(self._pool)
  
  @defer.inlineCallbacks
  def mongo_find_one_or_none(self, collection, query):
    col = getattr((yield self.db), collection)
    r = yield col.find_one(query)
    if not r:
      r = None
    defer.returnValue(r)

  @defer.inlineCallbacks
  def mongo_insert(self, collection, *args, **kwargs):
    col = getattr((yield self.db), collection)
    r = yield col.insert(*args, **kwargs)
    defer.returnValue(r)

  @defer.inlineCallbacks
  def mongo_save(self, collection, *args, **kwargs):
    col = getattr((yield self.db), collection)
    r = yield col.save(*args, **kwargs)
    defer.returnValue(r)

  @defer.inlineCallbacks
  def mongo_remove(self, collection, *args, **kwargs):
    col = getattr((yield self.db), collection)
    r = yield col.remove(*args, **kwargs)
    defer.returnValue(r)
  
  @defer.inlineCallbacks
  def mongo_ensure(self, collection, index):
    k = 'collection' + ''.join(list(index.iterkeys()))
    if k in self.ensured_indexes:
      defer.returnValue(True)
    else:
      col = getattr((yield self.db), collection)
      yield col.ensureIndex(index)
      defer.returnValue(True)
  

