# cycloauth

This is an OAuth 1.0a provider for [cyclone](https://github.com/fiorix/cyclone) It requires [oauth2](https://github.com/simplegeo/python-oauth2) and is based on [wsgioauth](http://pypi.python.org/pypi/wsgioauth). 

cycloauth provides:

 * A simple and compliant OAuth 1.0a provider
 * HMAC-SHA1 and PLAINTEXT signature methods
 * Pluggable storage backend
 * MongoDB storage backend bundled (using [txmongo](https://github.com/fiorix/mongo-async-python-driver/tree/master/txmongo))
 
I am still working on tests and compliancy however am using it for a production project and so it should see regular updates toward supporting various consumer libraries.

## Basic Usage

### 1. Clone, install requirements and install:

This should be done from within a `virtualenv`
 
    $ git clone git://github.com:/samuraisam/cycloauth
    $ cd cycloauth
    $ sudo pip install -r requirements.txt
    $ sudo pip install -e ./

### 2. Add cycloauth handlers to your application:
 
    import cyclone.web, cycloauth.provider
    
    # your application must include the provider mixin
    class Application(cyclone.web.Application, cycloauth.provider.OAuthApplicationMixin):
      def __init__(self, *args, **kwargs):
        handlers = [
          ('/myapp', myapp.web.RootHandler),
        ]
        # here cycloauth.provider.handlers() takes a dictionary of settings
        # which must be a dictionary, I recommend using your global application settings
        # we'll leave it blank for now to get something up and running
        settings = {'debug': True}
        handlers += handlers(settings)
        cyclone.web.Application.__init__(self, handlers, **settings)

By default this gives you a few URLs which are overridable in settings using the settings key in bold:

 * `/oauth/request_token` **oauth_request_token_url** used by clients to create a request token
 * `/oauth/authorize` **oauth_authorize_url** shown to users in a web browser to request authorization to the client, it uses a default handler which is overridable in settings (more on this later)
 * `/oauth/access_token` **oauth_access_token_url** used by clients to acquire an access token

### 3. Create a way to register applications with your service

You must provide a way to register new consumers with your service. The way in which you implement it is up to you however it must follow this common pattern:

    from cyclone.web import RequestHandler
    from cycloauth.provider import OAuthRequestHandlerMixin
    from twisted.internet import defer
    
    class RegisterApplicationHandler(RequestHandler, OAuthRequestHandlerMixin):
      @defer.inlineCallbacks
      @cyclone.web.asynchronous
      def get(self):
        c = yield self.application.oauth_storage.add_consumer()
        yield self.application.oauth_storage.save_consumer(c)
        self.write(dict(
          key=c.key,
          secret=c.secret
        ))
        self.finish()

This will generate a new consumer key/secret and save it to the oauth store. Most likely you will also want to store it somewhere in your database attached to another sort of user account.

### 4. Create a protected resource

Protecting a service with OAuth authentication is pretty easy. It is important to note that **ALL OAuth protected resources are required to be asynchronous**
    
    from cycloauth.provider import OAuthRequestHandlerMixin, oauth_authenticated
    from cyclone.web import RequestHandler
    
    class NativeProtectedMethodHandler(RequestHandler, OAuthRequestHandlerMixin):
      @oauth_authenticated
      def get(self):
        self.write(hashlib.md5(self.get_argument('omg')).hexdigest())
        self.finish()

