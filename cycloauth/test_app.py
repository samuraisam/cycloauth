import urllib, time, binascii, uuid, oauth2, hashlib, json
import cyclone.web, cyclone.httpclient, cyclone.auth, cyclone.escape
import cycloauth.provider
from twisted.internet import defer
from twisted.python import log


LE_TOKEN = None


class NativeMixin(cyclone.auth.OAuthMixin):
  _OAUTH_REQUEST_TOKEN_URL = "http://127.0.0.1:8000/oauth/request_token"
  _OAUTH_ACCESS_TOKEN_URL = "http://127.0.0.1:8000/oauth/access_token"
  _OAUTH_AUTHORIZE_URL = "http://127.0.0.1:8000/oauth/authorize"
  _OAUTH_NO_CALLBACKS = False
  _OAUTH_CALLBACK = 'http://127.0.0.1:8000/register/native/callback'
  
  def native_request(self, path, access_token=None, post_args=None, **args):
    url = path
    headers = {}
    if access_token:
      all_args = {}
      all_args.update(args)
      all_args.update(post_args or {})
      consumer_token = self._oauth_consumer_token()
      method = "POST" if post_args is not None else "GET"
      oauth = self._oauth_request_parameters(
          url, access_token, all_args, method=method)
      headers.update(self._oauth_header(path, oauth))
      #args.update(oauth)
    if args: url += "?" + urllib.urlencode(args)
    print headers
    if post_args is not None:
      return cyclone.httpclient.fetch(url, method="POST", postdata=urllib.urlencode(post_args), headers=headers)
    else:
      return cyclone.httpclient.fetch(url, headers=headers)
  
  def _oauth_header(self, uri, params):
    "this taken from oauth2/__init__.py Request.to_header"
    "https://github.com/simplegeo/python-oauth2/blob/master/oauth2/__init__.py"
    schema, rest = urllib.splittype(uri)
    if rest.startswith('//'):
      hierpart = '//'
    else:
      hierpart = ''
    host, rest = urllib.splithost(rest)
    realm = schema + ':' + hierpart + host
    escape = lambda s: urllib.quote(s.encode('utf-8'), safe='~')
    oauth_params = ((k, v) for k, v in params.iteritems() if k.startswith('oauth_'))
    stringy_params = ((k, escape(str(v))) for k, v in oauth_params)
    header_params = ('%s="%s"' % (k, v) for k, v in stringy_params)
    params_header = ','.join(header_params)
    auth_header = 'OAuth realm="%s"' % realm
    if params_header:
      auth_header = "%s, %s" % (auth_header, params_header)
    return {'Authorization': [auth_header]}
  
  def _oauth_consumer_token(self):
    return dict(
      key="omgnowai",
      secret="omgyeswai"
    )

  def _oauth_access_token_url(self, request_token, verifier=None):
    consumer_token = self._oauth_consumer_token()
    url = self._OAUTH_ACCESS_TOKEN_URL
    args = dict(
        oauth_consumer_key=consumer_token["key"],
        oauth_token=request_token["key"],
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp=str(int(time.time())),
        oauth_nonce=binascii.b2a_hex(uuid.uuid4().bytes),
        oauth_version="1.0",
    )
    if verifier:
      args['oauth_verifier'] = verifier
    signature = cyclone.auth._oauth_signature(consumer_token, "GET", url, args,
                                 request_token)
    args["oauth_signature"] = signature
    return url + "?" + urllib.urlencode(args)
    
  def _oauth_request_token_url(self, callback=None):
    consumer_token = self._oauth_consumer_token()
    url = self._OAUTH_REQUEST_TOKEN_URL
    args = dict(
        oauth_consumer_key=consumer_token["key"],
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp=str(int(time.time())),
        oauth_nonce=binascii.b2a_hex(uuid.uuid4().bytes),
        oauth_version="1.0",
    )
    if callback:
      args['oauth_callback'] = callback
    signature = cyclone.auth._oauth_signature(consumer_token, "GET", url, args)
    args["oauth_signature"] = signature
    return url + "?" + urllib.urlencode(args)


class NativeRegistrationHandler(cyclone.web.RequestHandler, NativeMixin):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def get(self):
    global LE_TOKEN
    LE_TOKEN = None
    yield cyclone.httpclient.fetch('http://127.0.0.1:8000/register/register_application')
    try:
      tok_resp = yield cyclone.httpclient.fetch(self._oauth_request_token_url(callback=self._OAUTH_CALLBACK))
      tok_bod = cyclone.auth._oauth_parse_response(tok_resp.body)
      if tok_bod:
        LE_TOKEN = tok_bod
        self.write(dict(
          authorize_url=self._OAUTH_AUTHORIZE_URL + '?' + urllib.urlencode(dict(
            oauth_token=tok_bod['key'],
          ))
        ))
    except Exception, e:
      log.err()
    finally:
      self.finish()


class NativeCallbackHandler(cyclone.web.RequestHandler, NativeMixin):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def get(self):
    global LE_TOKEN
    request_key = self.get_argument('oauth_token')
    request_token = LE_TOKEN
    try:
      acc_resp = yield cyclone.httpclient.fetch(
        self._oauth_access_token_url(request_token, verifier=self.get_argument('oauth_verifier')))
      print 'acc_resp', acc_resp.body
      acc_bod = cyclone.auth._oauth_parse_response(acc_resp.body)
      if acc_bod:
        request_token.update(acc_bod)
        LE_TOKEN = request_token
        print 'le_token', request_token
        self.write(request_token)
    except Exception, e:
        log.err()
    finally:
        self.finish()


class RegisterApplicationHandler(cyclone.web.RequestHandler, cycloauth.provider.OAuthRequestHandlerMixin):
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


class NativeProtectedMethodHandler(cyclone.web.RequestHandler, cycloauth.provider.OAuthRequestHandlerMixin):
  @cycloauth.provider.oauth_authenticated
  def get(self):
    self.write(hashlib.md5(self.get_argument('omg')).hexdigest())
    self.finish()
  
  @cycloauth.provider.oauth_authenticated
  def post(self):
    try:
      self.write(hashlib.md5(self.get_argument('omg')).hexdigest())
    except:
      log.err()
    self.finish()


class NativeProtectedMethodCallHandler(cyclone.web.RequestHandler, NativeMixin):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def get(self):
    tok = LE_TOKEN
    req = yield self.native_request('http://127.0.0.1:8000/native/protected_method', tok, omg='wtfef')
    req2 = yield self.native_request('http://127.0.0.1:8000/native/protected_method', tok, post_args={'omg': 'wtfomg'})
    self.write('get: ' + req.body)
    self.write('\n')
    self.write('post: ' + req2.body)
    self.finish()


class RunTestHandler(cyclone.web.RequestHandler):
  @defer.inlineCallbacks
  @cyclone.web.asynchronous
  def get(self):
    r = yield cyclone.httpclient.fetch('http://127.0.0.1:8000/register/native')
    print 'reg', r.body
    self.write('reg: ' + r.body)
    o = json.loads(r.body)['authorize_url']
    self.write('authorize_url: ' + o + '\n')
    r2 = yield cyclone.httpclient.fetch(o, followRedirect=1)
    self.write('access_token: ' + r2.body + '\n')
    #o2 = json.loads((yield cyclone.httpclient.fetch(o)).body)
    self.write('protected: ' + (yield cyclone.httpclient.fetch('http://127.0.0.1:8000/native/do_protected_method')).body)
    self.finish()


class Application(cyclone.web.Application, cycloauth.provider.OAuthApplicationMixin):
  def __init__(self):
    handlers = [
        (r'/register/native', NativeRegistrationHandler),
        (r'/register/native/callback', NativeCallbackHandler),
        (r'/register/register_application', RegisterApplicationHandler),
        (r'/native/do_protected_method', NativeProtectedMethodCallHandler),
        (r'/native/protected_method', NativeProtectedMethodHandler),
        (r'/run_simple_tests', RunTestHandler)
    ]
    settings = dict(debug=True, oauth_storage_factory='cycloauth.storage.mongodb.MongoDBStorage')
    handlers += cycloauth.provider.handlers(settings)
    cyclone.web.Application.__init__(self, handlers, **settings)

