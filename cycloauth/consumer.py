from oauth2 import Consumer as OAuthConsumer


class Consumer(OAuthConsumer):
  callback = None
