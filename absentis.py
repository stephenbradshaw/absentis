import os.path 
from burp import IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator, IScannerCheck, IScanIssue, IScannerInsertionPointProvider, IContextMenuFactory, IContextMenuInvocation, IScannerInsertionPoint, IScanIssue, IExtensionStateListener
import json
from java.io import PrintWriter
from javax.swing import JMenuItem
from java.util import List,ArrayList
import datetime
import threading


CONFIG_FILENAME = '.absentis.conf'
EXTENSION_NAME = 'Absentis'
INSERTION_POINT_NAME = 'Absentis URL insertion point'
GENERATOR_NAME = 'Absentis URL Generator Factory'

config_defaults = {
    'file_append_values' : [
        '.bak',
        '.bkp',
        '.backup',
        '.old',
        '.src',
        '.data',
        '.dev',
        '.inc',
        '.orig',
        '.original',
        '.copy',
        '.tmp',
        '.swp',
        '~'
    ],
    'rootdir_values' : [
        'robots.txt',
        'humans.txt',
        'security.txt',
        'sitemap.xml'
    ],
    'dir_values' : [
        'crossdomain.xml',
        'clientaccesspolicy.xml'
    ],
    'scanner_check' : True,
    'global_active_scan' : False, # for various reasons based on how the scanner is tuned this often isnt effectve, disable until fixed 
    'intruder_payload_generator' : True,
    'context_menu_active_scan' : True

}

# TODO
# zip, bz2, gz, tar, tar.bz2, tar.gz, .tgz, .rar
# git repo files
# windows copy
# directories with
# 8.3 filenames? including for filter bypassing
# replacing extensions too? .java, .inc, .config, .asa, and many of the above list
# 200 is a legit call
# 403 is worth a closer check 9 


class Parser:

    def __init__(self, config):
        self.config = config

    def _split_path(self, url):
        return [a[::-1] for a in url.split('?')[0][::-1].split('/', 1)][::-1]

    def parser_file_append(self, url):
        if url.endswith('/'):
            return []
        return [url.split('?')[0] + a for a in self.config['file_append_values']] 
        

    def parser_vim_swp(self, url):
        if url.endswith('/'):
            return []
        return [(lambda x: '{}/.{}.swp'.format(x[0], x[1]))(self._split_path(url))]


    def parser_rootdir(self, url):
        if url.count('/') == 1:
            return ['/{}'.format(a) for a in self.config['rootdir_values']]
        else:
            return []

    def parser_dir(self, url):
        return ['{}/{}'.format(self._split_path(url)[0], a) for a in self.config['dir_values']]

    def get_parser_output(self, url):
        out = []
        for parser in [a for a in dir(self) if a.startswith('parser_')]:
            out += getattr(self, parser)(url)
        return out
    



class BurpExtender(IBurpExtender):
    '''BurpExtender Class to register the extension with Burp Suite'''

    def registerExtenderCallbacks(self, callbacks):
        '''Interface method to register the extender callbacks'''
        config_file = os.path.join(os.path.expanduser("~"), CONFIG_FILENAME)
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        continue_load = True
        if not os.path.isfile(config_file):
            open(config_file, 'w').write(json.dumps(config_defaults, indent=4, sort_keys=True))
            stdout.println('Existing config file not found. Wrote default config file values to ~/{}'.format(CONFIG_FILENAME))
            config = config_defaults
        else:
            try:
                config = json.load(open(config_file))
                stdout.println('Loaded configuration from: ~/{}'.format(CONFIG_FILENAME))
            except Exception as e:
                stderr.println('An error occuring reading the config file ~/{}: {}.\nTerminating extension.'.format(CONFIG_FILENAME, e))
                contine_load = False

        if continue_load:
            callbacks.setExtensionName(EXTENSION_NAME)
            if config['intruder_payload_generator']:
                callbacks.registerIntruderPayloadGeneratorFactory(PayloadGeneratorFactory(callbacks, config))
                stdout.println('Intruder payload generator registered')
            if config['global_active_scan']:
                callbacks.registerScannerInsertionPointProvider(InsertionPointProvider(callbacks, config))
                stdout.println('Checks now registered to be performed as part of a regular Active Scan')
                config['scanner_check'] = True
            if config['context_menu_active_scan']:
                callbacks.registerContextMenuFactory(ContextMenu(callbacks, config))
                stdout.println('Context menu to actively scan selected request registered')
                config['scanner_check'] = True
            if config['scanner_check']:
                callbacks.registerScannerCheck(Scanner(callbacks, config))
                stdout.println('Scanner check registered')
            
            stdout.println('Extension loaded!')





class ContextMenu(IContextMenuFactory):

    def __init__(self, callbacks, config):
        self.callbacks  = callbacks
        self.config = config
        self.helpers = callbacks.getHelpers()

    def createMenuItems(self, IContextMenuInvocation):
        self.selectedMessages = IContextMenuInvocation.getSelectedMessages()
        menuItemList = ArrayList()
        menuItemList.add(JMenuItem("Actively scan request with Absentis", actionPerformed = self.onClick))
        return menuItemList


    def runScan(self):
        stderr = PrintWriter(self.callbacks.getStderr(), True)
        for message in self.selectedMessages:
            request = message.getRequest()
            http_service = message.getHttpService()
            a_request = self.helpers.analyzeRequest(http_service, request)
            url = '/' + str(a_request.getUrl()).split('/', 3)[-1]
            insertion_point = InsertionPoint(self.callbacks, self.config, request, url)
            if insertion_point.checkValid():
                for scanner in self.callbacks.getScannerChecks():
                    issues = scanner.doActiveScan(message, insertion_point)
                    for issue in issues:
                        url = str(issue.getUrl())
                        url = '{}/{}/{}'.format('/'.join(url.split('/')[:2]), url.split('/')[2].split(':')[0], url.split('/', 3)[-1]) # no port in hostname
                        exists = False 
                        for existing_issue in self.callbacks.getScanIssues(url):
                            if existing_issue.getIssueName() == issue.getIssueName():
                                exists = True
                        if not exists:
                            self.callbacks.addScanIssue(issue)
                        stderr.println('Finished scan')


    def onClick(self, event):
        t = threading.Thread(target=self.runScan)
        t.daemon = True
        t.start()


class StateLoader(IExtensionStateListener):

    def __init__(self, callbacks, config):
        self.callbacks = callbacks
        self.config = config

    def extensionUnloaded(self):
        pass





class Scanner(IScannerCheck):

    def __init__(self, callbacks, config):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.config = config


    def doPassiveScan(self, baseRequestResponse):
        # return None or a list of IScanIssue objects
        return None


    def doActiveScan(self,  baseRequestResponse, insertionPoint):
        # This implements the scan, including making a request/s, receiving the responses, 
        # creating scan issues for relevant issues and returning them or None
        # is called for each active scan, for each insertion point - filter for 
        stderr = PrintWriter(self.callbacks.getStderr(), True)
        stdout = PrintWriter(self.callbacks.getStdout(), True)
        out = None
        # filter for the insertion poitns we care about
        if insertionPoint.getInsertionPointName() == INSERTION_POINT_NAME or insertionPoint.getInsertionPointType() in [33, 37]:
            #stderr.println('Enabled insertion point {}'.format(insertionPoint.getInsertionPointName()))
            http_service = baseRequestResponse.getHttpService()
            host = http_service.getHost()
            port = http_service.getPort()
            useHttps = http_service.getProtocol() == 'https'
            parser = Parser(self.config)
            payloads = parser.get_parser_output(insertionPoint.getBaseValue())
            for payload in payloads:
                request = insertionPoint.buildRequest(self.helpers.stringToBytes(payload))                
                requestResponse = self.callbacks.makeHttpRequest(http_service, request)
                response = requestResponse.getResponse()
                analysed_response = self.helpers.analyzeResponse(response)
                if analysed_response.getStatusCode() == 200:
                    scanIssue = ScanIssue(self.callbacks, self.config, requestResponse, payload)
                    if not out:
                        out = []
                    out.append(scanIssue)
                #stderr.println('Finished for: {}'.format(payload))
        return out
                

    def consolidateDuplicateIssues(self, existingIssue, newIssue): # typeIScanIssue
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0 # 0 for both issues, -1 for existing only, 1 for the new issue only



class InsertionPoint(IScannerInsertionPoint):

    def __init__(self, callbacks, config, request, url): 
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.request = self.helpers.bytesToString(request)
        self.url = url
        self.start = self.request.find(url)
        self.end = self.start+len(url)
        self.enabled = True # disable by default so this is used only for this extensions Scanner
        self.stderr = PrintWriter(self.callbacks.getStderr(), True)

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def checkValid(self):
        return self.start > 0

    def buildRequest(self, payload):
        #self.stderr.println('buildRequest called')
        #if self.enabled:
        p = self.request[:self.start] + self.helpers.bytesToString(payload) + self.request[self.end:]
        return self.helpers.stringToBytes(p)
        #else:
            #return None

    def getBaseValue(self):
        #self.stderr.println('getBaseValue called')
        #if self.enabled:
        return self.url
        #else:
        #    return None


    def getInsertionPointName(self):
        #self.stderr.println('getInsertionPointName called')
        return INSERTION_POINT_NAME


    def getInsertionPointType(self):
        #self.stderr.println('getInsertionPointType called')
        return '\x65' #INS_URL_PATH_FILENAME 37 or INS_URL_PATH_FOLDER 33


    def getPayloadOffsets(self, payload):
        #self.stderr.println('getPayloadOffsets called')
        return [self.start, self.start+len(payload)] if (self.checkValid() and self.enabled) else None



#TODO
# try and find a way to only have these registered insertion points used for this extensions scans
# at the moment if this insertion point provider is registered it is used for all payloads
# the scan tuning will quickly stop sending to this unless custom settings are used
# this makes the integration into regular scan workflow unusable
class InsertionPointProvider(IScannerInsertionPointProvider):

    def __init__(self, callbacks, config):
        self.callbacks = callbacks
        self.config = config
        self.helpers = callbacks.getHelpers()


    def getInsertionPoints(self, baseRequestResponse):
        raw_request = baseRequestResponse.getRequest()
        http_service = baseRequestResponse.getHttpService()
        a_request = self.helpers.analyzeRequest(http_service, raw_request)
        url = '/' + str(a_request.getUrl()).split('/', 3)[-1] # the file path portion of url, e.g. /robots.txt
        
        insertion_points = None
        if url: # there should always be a url, but lets check
            ip = InsertionPoint(self.callbacks, self.config, raw_request, url)
            if ip.checkValid():
                insertion_points = [ip]

        return insertion_points
        #stderr = PrintWriter(self.callbacks.getStderr(), True)
        #stderr.println('Not implemented')

        #TODO
        # create an InsertionPoint that identifies the url in a request 
        # the right click option will need to duplicate this
        
        #return None


class ScanIssue(IScanIssue):

    def __init__(self, callbacks, config, requestResponse, payload):
        self.callbacks = callbacks
        self.stderr = PrintWriter(self.callbacks.getStderr(), True)
        #self.stderr.println('Init ScanIssue')
        self.config = config
        self.payload = payload
        self.requestResponse = requestResponse
        self.http_service = requestResponse.getHttpService()

        a_request = self.callbacks.getHelpers().analyzeRequest(self.http_service, requestResponse.getRequest())
        self.url1 = a_request.getUrl()

        #self.stderr.println('Finished Init ScanIssue')

    def getUrl(self):
        return self.url1  


    def getIssueName(self):
        return 'File discovered: {}'.format(self.payload)


    def getIssueType(self):
        return 0x006000d8 # https://portswigger.net/kb/issues

    def getIssueDetail(self):
        return 'No additional detail.'

    def getRemediationDetail(self):
        return 'Check if the file can be removed.'

    def getSeverity(self):
        return 'Information' # "High", "Medium", "Low", "Information" or "False positive".


    def getConfidence(self):
        return 'Certain' # Firm, Tentative


    def getIssueBackground(self):
        return 'Found a file: {}'.format(self.payload)

    def getRemediationBackground(self):
        return 'File is potentially an interesting one, have a look at it.'

    def getHttpMessages(self):
        return [self.requestResponse]

    def getHttpService(self):
        return self.http_service




class PayloadGeneratorFactory(IIntruderPayloadGeneratorFactory):

    def __init__(self, callbacks, config):
        self.callbacks = callbacks
        self.config = config

    def getGeneratorName(self):
        return GENERATOR_NAME


    def createNewInstance(self, attack):
        return PayloadGenerator(self.callbacks, self.config, attack)



class PayloadGenerator(IIntruderPayloadGenerator):


    def __init__(self, callbacks, config, attack):
        self.callbacks = callbacks
        self.config = config
        self.helpers = callbacks.getHelpers()
        self.parser = Parser(config)
        self.payloads = None
        self.morePayloads = True


    def hasMorePayloads(self):
        return self.morePayloads


    def getNextPayload(self, baseValue):
        if isinstance(self.payloads, type(None)): # first run
            self.payloads = self.parser.get_parser_output(self.helpers.bytesToString(baseValue))
        if len(self.payloads):
            payload = self.payloads.pop(0)
            if len(self.payloads) == 0:
                self.morePayloads = False
            return payload
        else: # this code path should never be reached
            self.config.strerr.println('An error occured when generating payloads!')
            
 