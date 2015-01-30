'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import sys, os, string, ast, json

try:
    import xml.etree.cElementTree as ET
    from xml.etree.cElementTree import Element, ElementTree
except ImportError:
    import xml.etree.ElementTree as ET
    from xml.etree.ElementTree import Element, ElementTree
    
the_config = None
    
CONST_API_CON_INFO = "api_con_info"
CONST_API_CON_INFO_HOST = "api_con_info_host"
CONST_API_CON_INFO_PORT = "api_con_info_port"
CONST_API_RESTFUL_CON_INFO_PORT = "api_restful_con_info_port"
CONST_APPNAME = "appname"
CONST_AUTH = "auth"
CONST_AUTO_SHARE_WORKSPACE = "auto_share_workspace"
CONST_CONFIG_PATH = "config_path"
CONST_DATA_PATH = "data_path"
CONST_DEBUG_STATUS = "debug_status"
CONST_DEFAULT_CATEGORY = "default_category"
CONST_DEFAULT_TEMP_PATH = "default_temp_path"
CONST_FONT = "font"
CONST_HOME_PATH = "home_path"
CONST_HOST_TREE_TOGGLE = "host_tree_toggle"
CONST_HSTACTIONS_PATH = "hstactions_path"
CONST_ICONS_PATH = "icons_path"
CONST_IMAGE_PATH = "image_path"
CONST_LOG_CONSOLE_TOGGLE = "log_console_toggle"
CONST_NETWORK_LOCATION = "network_location"
CONST_PERSISTENCE_PATH = "persistence_path"
CONST_PERSPECTIVE_VIEW = "perspective_view"
CONST_REPO_PASSWORD = "repo_password"
CONST_COUCH_URI = "couch_uri"
CONST_COUCH_REPLICS = "couch_replics"
CONST_COUCH_ISREPLICATED = "couch_is_replicated"
CONST_REPO_URL = "repo_url"
CONST_REPO_USER = "repo_user"
CONST_REPORT_PATH = "report_path"
CONST_SHELL_MAXIMIZED = "shell_maximized"
CONST_VERSION = "version"
CONST_UPDATEURI = "updates_uri"
CONST_TKTURI = "tickets_uri"
CONST_TKTAPIPARAMS = "tickets_api"
CONST_TKTTEMPLATE = "tickets_template"

CONST_LAST_WORKSPACE = "last_workspace"
CONST_PLUGIN_SETTINGS = "plugin_settings"

                                                                
DEFAULT_XML = os.path.dirname(__file__) +  "/default.xml"

 
class Configuration:

    def __init__(self, xml_file=DEFAULT_XML):
        """ Initializer that handles a configuration automagically. """

        self.filepath = xml_file

        if self._isConfig(): self._getConfig()

    def _isConfig(self):
        """ Checks whether the given file exists and belongs 
        to faraday's configuration syntax"""

        root = f = None
        
        try:
            f = open(self.filepath, 'rb')
            try:
                for event, elem in ET.iterparse(f, ('start', )):
                    root = elem.tag
                    break
            except SyntaxError, err:
                print "Not an xml file.\n %s" % (err)
                return False

        except IOError, err:
            print "Error while opening file.\n%s. %s" % (err, self.filepath)
            return False
            
        finally:
            if f: f.close()

        return (root == "faraday")

    def _getTree(self):
        """ Returns an XML tree read from file. """

        f = open(self.filepath)
        try:
            tree = ET.fromstring(f.read())
        except SyntaxError, err:
            print "SyntaxError: %s. %s" % (err, self.filepath)
            return None
        return tree

    def _getValue(self, tree, var, default = None):
        """ Returns generic value from a variable on an XML tree. """

        elem = tree.findall(var)
        if not(elem):
            return default

        return elem[0].text

    def _getConfig(self):
        """ Gathers all configuration data from self.filepath, and
            completes private attributes with such information. """

        tree = self._getTree()
        if tree:                                                          
            self._api_con_info_host = self._getValue(tree, CONST_API_CON_INFO_HOST)
            self._api_con_info_port = self._getValue(tree, CONST_API_CON_INFO_PORT)
            self._api_restful_con_info_port = self._getValue(tree, CONST_API_RESTFUL_CON_INFO_PORT)
            self._api_con_info = self._getValue(tree, CONST_API_CON_INFO)
            self._appname = self._getValue(tree, CONST_APPNAME)
            self._auth = self._getValue(tree, CONST_AUTH)
            self._auto_share_workspace = self._getValue(tree, CONST_AUTO_SHARE_WORKSPACE)
            self._config_path = self._getValue(tree, CONST_CONFIG_PATH)
            self._data_path = self._getValue(tree, CONST_DATA_PATH)
            self._debug_status = self._getValue(tree, CONST_DEBUG_STATUS)
            self._default_category = self._getValue(tree, CONST_DEFAULT_CATEGORY)
            self._default_temp_path = self._getValue(tree, CONST_DEFAULT_TEMP_PATH)
            self._font = self._getValue(tree, CONST_FONT)
            self._home_path = self._getValue(tree, CONST_HOME_PATH)
            self._host_tree_toggle = self._getValue(tree, CONST_HOST_TREE_TOGGLE)
            self._hsactions_path = self._getValue(tree, CONST_HSTACTIONS_PATH)
            self._icons_path = self._getValue(tree, CONST_ICONS_PATH)
            self._image_path = self._getValue(tree, CONST_IMAGE_PATH)
            self._log_console_toggle = self._getValue(tree, CONST_LOG_CONSOLE_TOGGLE)
            self._network_location = self._getValue(tree, CONST_NETWORK_LOCATION)
            self._persistence_path = self._getValue(tree, CONST_PERSISTENCE_PATH)
            self._perspective_view = self._getValue(tree, CONST_PERSISTENCE_PATH)
            self._repo_password = self._getValue(tree, CONST_REPO_PASSWORD)
            self._couch_uri = self._getValue(tree, CONST_COUCH_URI, default = "")
            self._couch_replics = self._getValue(tree, CONST_COUCH_REPLICS, default = "")
            self._couch_is_replicated = bool(self._getValue(tree, CONST_COUCH_ISREPLICATED, default = False))
            self._repo_url = self._getValue(tree, CONST_REPO_URL)
            self._repo_user = self._getValue(tree, CONST_REPO_USER)
            self._report_path = self._getValue(tree, CONST_REPORT_PATH)
            self._shell_maximized = self._getValue(tree, CONST_SHELL_MAXIMIZED)
            self._version = self._getValue(tree, CONST_VERSION)
            self._last_workspace = self._getValue(tree, CONST_LAST_WORKSPACE, default = "untitled")
            self._plugin_settings = json.loads(self._getValue(tree, CONST_PLUGIN_SETTINGS, default = "{}"))

            self._updates_uri = self._getValue(tree, CONST_UPDATEURI, default = "https://www.faradaysec.com/scripts/updates.php")
            self._tkts_uri = self._getValue(tree, CONST_TKTURI,default = "https://www.faradaysec.com/scripts/listener.php")
            self._tkt_api_params = self._getValue(tree, CONST_TKTAPIPARAMS,default ="{}")
            self._tkt_template = self._getValue(tree, CONST_TKTTEMPLATE,default ="{}")


                        
    def getApiConInfo(self):
        if str(self._api_con_info_host) == "None" or str(self._api_con_info_port) == "None":
            return None
        return self._api_con_info_host, int(self._api_con_info_port)

    def getApiRestfulConInfo(self):
        if str(self._api_con_info_host) == "None" or str(self._api_restful_con_info_port) == "None":
            return None
        return self._api_con_info_host, int(self._api_restful_con_info_port)        
                                  
    def getApiConInfoHost(self):
        return self._api_con_info_host
    
    def getApiConInfoPort(self):
        return self._api_con_info_port
    
    def getApiRestfulConInfoPort(self):
        return self._api_restful_con_info_port

    def getAppname(self):
        return self._appname

    def getAuth(self):
        return self._auth

    def getAutoShareWorkspace(self):
        return self._auto_share_workspace

    def getConfigPath(self):
        return os.path.expanduser(self._config_path)

    def getDataPath(self):
        return os.path.expanduser(self._data_path)

    def getDebugStatus(self):
        return int(self._debug_status)

    def getDefaultCategory(self):
        return self._default_category

    def getDefaultTempPath(self):
        return os.path.expanduser(self._default_temp_path)
    
    def getFont(self):
        return self._font

    def getHomePath(self):
        return os.path.expanduser(self._home_path)

    def getHostTreeToggle(self):
        return self._host_tree_toggle

    def getHsactionsPath(self):
        return os.path.expanduser(self._hsactions_path)

    def getIconsPath(self):
        return os.path.expanduser(self._icons_path)

    def getImagePath(self):
        return os.path.expanduser(self._image_path)

    def getLogConsoleToggle(self):
        return self._log_console_toggle

    def getNetworkLocation(self):
        return self._network_location

    def getPersistencePath(self):
        return os.path.expanduser(self._persistence_path)

    def getPerspectiveView(self):
        return self._perspective_view

    def getCouchURI(self):
        return self._couch_uri

    def getCouchReplics(self):
        return self._couch_replics

    def getCouchIsReplicated(self):
        return self._couch_is_replicated

    def getRepoPassword(self):
        return self._repo_password

    def getRepoUrl(self):
        return self._repo_url

    def getRepoUser(self):
        return self._repo_user

    def getReportPath(self):
        return os.path.expanduser(self._report_path)

    def getShellMaximized(self):
        return self._shell_maximized

    def getVersion(self):
        return self._version

    def getLastWorkspace(self):
        return self._last_workspace

    def getPluginSettings(self):
        return self._plugin_settings

    def getUpdatesUri(self):
        return self._updates_uri

    def getTktPostUri(self):
        return self._tkts_uri

    def getApiParams(self):
        return self._tkt_api_params

    def getTktTemplate(self):
        return self._tkt_template

                        

    def setLastWorkspace(self, workspaceName):
        self._last_workspace = workspaceName

    def setApiConInfo(self, val1, val2):
        self._api_con_info = val1, val2
        self.setApiConInfoHost(val1)
        self.setApiConInfoPort(val2)

    def setApiRestfulConInfo(self, val1, val2):
        self._api_con_info = val1, val2
        self.setApiConInfoHost(val1)
        self.setApiRestfulConInfoPort(val2)        
        
    def setApiConInfoHost(self, val):
        self._api_con_info_host = val
    
    def setApiConInfoPort(self, val):
        self._api_con_info_port = str(val)
    
    def setApiRestfulConInfoPort(self, val):
        self._api_restful_con_info_port = str(val)

    def setAppname(self, val):
        self._appname = val

    def setAuth(self, val):
        self._auth = val

    def setAutoShareWorkspace(self, val):
        self._auto_share_workspace = val

    def setConfigPath(self, val):
        self._config_path = val

    def setDataPath(self, val):
        self._data_path = val

    def setDebugStatus(self, val):
        self._debug_status = int(val)

    def setDefaultCategory(self, val):
        self._default_category = val

    def setDefaultTempPath(self, val):
        self._default_temp_path = val
    
    def setFont(self, val):
        self._font = val

    def setHomePath(self, val):
        self._home_path = val

    def setHostTreeToggle(self, val):
        self._host_tree_toggle = val

    def setHsactionsPath(self, val):
        self._hsactions_path = val

    def setIconsPath(self, val):
        self._icons_path = val

    def setImagePath(self, val):
        self._image_path = val

    def setLogConsoleToggle(self, val):
        self._log_console_toggle = val

    def setNetworkLocation(self, val):
        self._network_location = val

    def setPersistencePath(self, val):
        self._persistence_path = val

    def setPerspectiveView(self, val):
        self._perspective_view = val

    def setRepoPassword(self, val):
        self._repo_password = val

    def setRepoUrl(self, val):
        self._repo_url = val

    def setRepoUser(self, val):
        self._repo_user = val

    def setReportPath(self, val):
        self._report_path = val

    def setShellMaximized(self, val):
        self._shell_maximized = val

    def setVersion(self, val):
        self._version = val

    def setCouchUri(self, uri): 
        self._couch_uri = uri

    def setCouchIsReplicated(self, is_it):
        self._couch_is_replicated = is_it

    def setCouchReplics(self, urls):
        self._couch_replics = urls

    def setPluginSettings(self, settings):
        self._plugin_settings = settings
    
    def indent(self, elem, level=0):
        """ Indents the tree to make a pretty view of it. """

        i = "\n" + level*"  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                self.indent(elem, level+1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i


    def saveConfig(self, xml_file="~/.faraday/config/user.xml"):
        """ Saves XML config on new file. """

        ROOT = Element("faraday")
        
        API_CON_INFO_HOST = Element(CONST_API_CON_INFO_HOST)
        API_CON_INFO_HOST.text = self.getApiConInfoHost()
        ROOT.append(API_CON_INFO_HOST)
        
        API_CON_INFO_PORT = Element(CONST_API_CON_INFO_PORT)
        API_CON_INFO_PORT.text = str(self.getApiConInfoPort())
        ROOT.append(API_CON_INFO_PORT)

        API_RESTFUL_CON_INFO_PORT = Element(CONST_API_RESTFUL_CON_INFO_PORT)
        API_RESTFUL_CON_INFO_PORT.text = str(self.getApiRestfulConInfoPort())
        ROOT.append(API_RESTFUL_CON_INFO_PORT)        
        
        APPNAME = Element(CONST_APPNAME)
        APPNAME.text = self.getAppname()
        ROOT.append(APPNAME)

        AUTH = Element(CONST_AUTH, encrypted="no", algorithm="OTR")
        AUTH.text = self.getAuth()
        ROOT.append(AUTH)

        AUTO_SHARE_WORKSPACE = Element(CONST_AUTO_SHARE_WORKSPACE)
        AUTO_SHARE_WORKSPACE.text = self.getAutoShareWorkspace()
        ROOT.append(AUTO_SHARE_WORKSPACE)

        CONFIG_PATH = Element(CONST_CONFIG_PATH)
        CONFIG_PATH.text = self.getConfigPath()
        ROOT.append(CONFIG_PATH)

        DATA_PATH = Element(CONST_DATA_PATH)
        DATA_PATH.text = self.getDataPath()
        ROOT.append(DATA_PATH)

        DEBUG_STATUS = Element(CONST_DEBUG_STATUS)
        DEBUG_STATUS.text = str(self.getDebugStatus())
        ROOT.append(DEBUG_STATUS)

        DEFAULT_CATEGORY = Element(CONST_DEFAULT_CATEGORY)
        DEFAULT_CATEGORY.text = self.getDefaultCategory()
        ROOT.append(DEFAULT_CATEGORY)

        DEFAULT_TEMP_PATH = Element(CONST_DEFAULT_TEMP_PATH)
        DEFAULT_TEMP_PATH.text = self.getDefaultTempPath()
        ROOT.append(DEFAULT_TEMP_PATH)

        FONT = Element(CONST_FONT)
        FONT.text = self.getFont()
        ROOT.append(FONT)

        HOME_PATH = Element(CONST_HOME_PATH)
        HOME_PATH.text = self.getHomePath()
        ROOT.append(HOME_PATH)


        HOST_TREE_TOGGLE = Element(CONST_HOST_TREE_TOGGLE)
        HOST_TREE_TOGGLE.text = self.getHostTreeToggle()
        ROOT.append(HOST_TREE_TOGGLE)

        HSTACTIONS_PATH = Element(CONST_HSTACTIONS_PATH)
        HSTACTIONS_PATH.text = self.getHsactionsPath()
        ROOT.append(HSTACTIONS_PATH)

        ICONS_PATH = Element(CONST_ICONS_PATH)
        ICONS_PATH.text = self.getIconsPath()
        ROOT.append(ICONS_PATH)

        IMAGE_PATH = Element(CONST_IMAGE_PATH)
        IMAGE_PATH.text = self.getImagePath()
        ROOT.append(IMAGE_PATH)

        LOG_CONSOLE_TOGGLE = Element(CONST_LOG_CONSOLE_TOGGLE)
        LOG_CONSOLE_TOGGLE.text = self.getLogConsoleToggle()
        ROOT.append(LOG_CONSOLE_TOGGLE)

        NETWORK_LOCATION = Element(CONST_NETWORK_LOCATION)
        NETWORK_LOCATION.text = self.getNetworkLocation()
        ROOT.append(NETWORK_LOCATION)

        PERSISTENCE_PATH = Element(CONST_PERSISTENCE_PATH)
        PERSISTENCE_PATH.text = self.getPersistencePath()
        ROOT.append(PERSISTENCE_PATH)

        PERSPECTIVE_VIEW = Element(CONST_PERSPECTIVE_VIEW)
        PERSPECTIVE_VIEW.text = self.getPerspectiveView()
        ROOT.append(PERSPECTIVE_VIEW)

        REPO_PASSWORD = Element(CONST_REPO_PASSWORD)
        REPO_PASSWORD.text = self.getRepoPassword()
        ROOT.append(REPO_PASSWORD)

        REPO_URL = Element(CONST_REPO_URL, type="SVN")
        REPO_URL.text = self.getRepoUrl()
        ROOT.append(REPO_URL)

        REPO_USER = Element(CONST_REPO_USER)
        REPO_USER.text = self.getRepoUser()
        ROOT.append(REPO_USER)

        REPORT_PATH = Element(CONST_REPORT_PATH)
        REPORT_PATH.text = self.getReportPath()
        ROOT.append(REPORT_PATH)

        SHELL_MAXIMIZED = Element(CONST_SHELL_MAXIMIZED)
        SHELL_MAXIMIZED.text = self.getShellMaximized()
        ROOT.append(SHELL_MAXIMIZED)

        LAST_WORKSPACE = Element(CONST_LAST_WORKSPACE)
        LAST_WORKSPACE.text = self.getLastWorkspace()
        ROOT.append(LAST_WORKSPACE)

        COUCH_URI = Element(CONST_COUCH_URI)
        COUCH_URI.text = self.getCouchURI()
        ROOT.append(COUCH_URI)

        COUCH_IS_REPLICATED = Element(CONST_COUCH_ISREPLICATED)
        COUCH_IS_REPLICATED.text = str(self.getCouchIsReplicated())
        ROOT.append(COUCH_IS_REPLICATED)

        COUCH_REPLICS = Element(CONST_COUCH_REPLICS)
        COUCH_REPLICS.text = self.getCouchReplics()
        ROOT.append(COUCH_REPLICS)

        VERSION = Element(CONST_VERSION)
        VERSION.text = self.getVersion()
        ROOT.append(VERSION)

        PLUGIN_SETTINGS = Element(CONST_PLUGIN_SETTINGS)
        PLUGIN_SETTINGS.text = json.dumps(self.getPluginSettings())
        ROOT.append(PLUGIN_SETTINGS)

        UPDATE_URI = Element(CONST_UPDATEURI)
        UPDATE_URI.text = self.getUpdatesUri()
        ROOT.append(UPDATE_URI)

        TKT_URI = Element(CONST_TKTURI)
        TKT_URI.text = self.getTktPostUri()
        ROOT.append(TKT_URI)

        TKT_APIPARAMS = Element(CONST_TKTAPIPARAMS)
        TKT_APIPARAMS.text = self.getApiParams()
        ROOT.append(TKT_APIPARAMS)

        TKT_TEMPLATE = Element(CONST_TKTTEMPLATE)
        TKT_TEMPLATE.text = self.getTktTemplate()
        ROOT.append(TKT_TEMPLATE)

        self.indent(ROOT, 0)                                                          
        xml_file = os.path.expanduser(xml_file)
        ElementTree(ROOT).write(xml_file)                                      
        
def getInstanceConfiguration():
    global the_config
    if the_config is None:                                                                                           
        if os.path.exists(os.path.expanduser("~/.faraday/config/user.xml")):
            the_config = Configuration(os.path.expanduser("~/.faraday/config/user.xml"))
        else:
            the_config = Configuration(os.path.expanduser("~/.faraday/config/config.xml"))
    return the_config


                           
                                     
 
                                     
                                 

                                          
                                         
                                                            
                                                                
                                                              
