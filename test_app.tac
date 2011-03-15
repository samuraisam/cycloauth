from twisted.application import service, internet
from cycloauth.test_app import Application

thapp = Application()
application = service.Application("thapp")

internet.TCPServer(8000, thapp, interface="127.0.0.1").setServiceParent(application)