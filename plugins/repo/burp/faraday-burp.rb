#!/usr/bin/ruby
###
## Faraday Penetration Test IDE - Community Version
## Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###
#__author__     = "Francisco Amato"
#__copyright__  = "Copyright (c) 2014, Infobyte LLC"
#__credits__    = ["Francisco Amato"]
#__version__    = "1.1.0"
#__maintainer__ = "Francisco Amato"
#__email__      = "famato@infobytesec.com"
#__status__     = "Development"

require 'java'
require "xmlrpc/client"
require "pp"



#FARADAY CONF:
RPCSERVER="http://127.0.0.1:9876/" ##cambiar variable
IMPORTVULN=1 #1 if you like to import the current vulnerabilities, or 0 if you only want to import new vulns
PLUGINVERSION="Faraday v1.1 Ruby"
#Tested: Burp Professional v1.5.18

XMLRPC::Config.module_eval do
    remove_const :ENABLE_NIL_PARSER
    const_set :ENABLE_NIL_PARSER, true
end
java_import 'burp.IBurpExtender'
java_import 'burp.IHttpListener'
java_import 'burp.IProxyListener'
java_import 'burp.IScannerListener'
java_import 'burp.IExtensionStateListener'
java_import 'burp.IExtensionHelpers'
java_import 'burp.IContextMenuFactory'
java_import 'java.net.InetAddress'
java_import 'javax.swing.JMenuItem'

class BurpExtender
  include IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener,IContextMenuFactory
    
  #
  # implement IBurpExtender
  #
  
  def	registerExtenderCallbacks(callbacks)
      
    # keep a reference to our callbacks object
    @callbacks = callbacks

    #Connect Rpc server
    @server = XMLRPC::Client.new2(RPCSERVER)
    @helpers = callbacks.getHelpers()
    
    # set our extension name
    callbacks.setExtensionName(PLUGINVERSION)
    
    # obtain our output stream
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)
    
    # Get current vulnerabilities
    if IMPORTVULN == 1
      param = @server.call("devlog", "[BURP] Importing issues")
      callbacks.getScanIssues(nil).each do |issue|
        newScanIssue(issue)
      end
    end 

    # Register a factory for custom context menu items
    callbacks.registerContextMenuFactory(self)

    # register ourselves as a Scanner listener
    callbacks.registerScannerListener(self)
    
    # register ourselves as an extension state listener
    callbacks.registerExtensionStateListener(self)

  end
  

  #
  # implement menu
  #
 
  # Create a menu item if the appropriate section of the UI is selected
  def createMenuItems(invocation)
      
      menu = []

      # Which part of the interface the user selects
      ctx = invocation.getInvocationContext()

      # Sitemap history, Proxy History will show menu item if selected by the user
      @stdout.println('Menu TYPE: %s\n' % ctx)
      if ctx == 5 or ctx == 6

          faradayMenu = JMenuItem.new("Send to Faraday", nil)

          faradayMenu.addActionListener do |e|
             eventScan(invocation)
          end

          menu.push(faradayMenu)
      end
      
      return menu
  end

  #
  # event click function
  #
  def eventScan(invocation)

      invMessage = invocation.getSelectedMessages()
      invMessage.each do |m|
        newScanIssue(m,1)
      end
  end
  
  #
  # implement IScannerListener
  #
  def newScanIssue(issue, information=nil)


    host=issue.getHost()
    port=issue.getPort().to_s()
    url = issue.getUrl()
    ip=InetAddress.getByName(issue.getHttpService().getHost()).getHostAddress()
    
    issuename="Analyzing: "
    severity="Information"
    desc="This request was manual send it using burp"
    
    if information == nil
      desc=issue.getIssueDetail().to_s
      desc+="<br/>Resolution:" + issue.getIssueBackground().to_s
      severity=issue.getSeverity().to_s
      issuename=issue.getIssueName().to_s
    end

    @stdout.println("New scan issue host: " +host +",name:"+ issuename +",IP:" + ip)

    begin
      param = @server.call("devlog", "[BURP] New issue generation")

      h_id = @server.call("createAndAddHost",ip, "unknown")
      i_id = @server.call("createAndAddInterface",h_id, ip,"00:00:00:00:00:00", ip, "0.0.0.0", "0.0.0.0",[],
                          "0000:0000:0000:0000:0000:0000:0000:0000","00","0000:0000:0000:0000:0000:0000:0000:0000",
                          [],"",host)

      s_id = @server.call("createAndAddServiceToInterface",h_id, i_id, issue.getProtocol(),"tcp",[port],"open")

      #Save website
      n_id = @server.call("createAndAddNoteToService",h_id,s_id,"website","")
      n2_id = @server.call("createAndAddNoteToNote",h_id,s_id,n_id,host,"")

      if information
        #@stdout.println(issue.methods)
        req= @helpers.analyzeRequest(issue.getRequest())

        #TODO: Actually Get all parameters, cookies, jason, url, maybe we should get only url,get/post parameters
        #TODO: We don't send response because queue bug in faraday.
        param=""
        req.getParameters().each { |p| param += "%s" % p.getType() +":"+p.getName()+"="+p.getValue()+","}

        issuename+= "("+issue.getUrl().getPath()[0,20]+")"
        v_id = @server.call("createAndAddVulnWebToService",h_id, s_id, issuename,
               desc,[],severity,host,issue.getUrl().to_s,issue.getRequest().to_s,
               "response",req.getMethod().to_s,"",param,"","")
      else
        unless issue.getHttpMessages().nil? #issues with request #IHttpRequestResponse
          @stdout.println("[**] issue host: " +host +",name:"+ issuename +",IP:" + ip)
          c=0
          issue.getHttpMessages().each do |m|
            req= @helpers.analyzeRequest(m.getRequest())

            #TODO: Actually Get all parameters, cookies, jason, url, maybe we should get only url,get/post parameters
            param=""
            req.getParameters().each { |p| param += "%s" % p.getType() +":"+p.getName()+"="+p.getValue()+","}

            v_id = @server.call("createAndAddVulnWebToService",h_id, s_id, issuename,
                   desc,[],severity,host,m.getUrl().to_s,m.getRequest().to_s,
                   "response",req.getMethod().to_s,"",param,"","")
            c=c+1
          end
          if c==0
            v_id = @server.call("createAndAddVulnWebToService",h_id, s_id, issuename.to_s,
                   desc,[],severity,host,issue.getUrl().to_s,"",
                   "response","","","/","","")
            
          end
        end
      end
      
    rescue XMLRPC::FaultException => e
      puts "-----\nError:"
      puts e.faultCode
      puts e.faultString
    end
  end

  def extensionUnloaded()

  end

end      
