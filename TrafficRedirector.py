'''
Traffic Redirector is a simple Burp extension which helps you to redirect
certain network traffic or only specific requests sent by Burp tools. It does
so by providing a proxy and a HTTP listener which allow you to redirect e.g
one specific request to another server or redirect all traffic from one
specific domain to another.
'''

__description__ = 'Traffic redirector plugin for Burp Suite'
__author__ = 'Gabor Seljan'
__version__ = '0.1'
__date__ = '2016/11/19'

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Traffic Redirector')
        callbacks.registerProxyListener(self)
        callbacks.registerHttpListener(self)
        return

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:

            TO_PROT = 'http'
            TO_HOST = '127.0.0.1'
            TO_PORT = 8000

            FROM_URLS = []
            for path in ['foo', 'bar']:
                FROM_URLS.append('http://example.com:80/' + path)

            TO_BASE_URL = TO_PROT + '://' + TO_HOST + ':' + str(TO_PORT)

            messageInfo = message.getMessageInfo()
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            requestUrl = str(requestInfo.getUrl())
            if (requestUrl in FROM_URLS):
                TO_URL = URL(TO_BASE_URL + requestUrl[requestUrl.rfind('/'):])
                self._callbacks.printOutput('Redirecting request from %s to %s' % (requestUrl, str(TO_URL)))
                messageInfo.setHttpService(self._helpers.buildHttpService(TO_HOST, TO_PORT, TO_PROT))
                messageInfo.setRequest(self._helpers.buildHttpRequest(TO_URL))
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:

            FROM_HOST = 'foo.example.com'

            TO_PROT = 'http'
            TO_HOST = 'bar.example.com'
            TO_PORT = 80

            httpService = messageInfo.getHttpService()
            if (FROM_HOST == httpService.getHost()):
                request = messageInfo.getRequest()
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                requestHeaders = requestInfo.getHeaders()
                requestBody = request[requestInfo.getBodyOffset():]

                for i in range(len(requestHeaders)):
                    if (str(requestHeaders[i]).startswith('Host:')):
                        requestHeaders[i] = 'Host: %s' % TO_HOST
                        break

                self._callbacks.printOutput('Redirecting request from %s to %s' % (FROM_HOST, TO_HOST))
                messageInfo.setHttpService(self._helpers.buildHttpService(TO_HOST, TO_PORT, TO_PROT))
                messageInfo.setRequest(self._helpers.buildHttpMessage(requestHeaders, requestBody))
        return