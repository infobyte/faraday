#!/usr/bin/ruby
###
## Faraday Penetration Test IDE - Community Version
## Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###
#__author__     = "Francisco Amato"
#__copyright__  = "Copyright (c) 2013, Infobyte LLC"
#__credits__    = ["Francisco Amato"]
#__version__    = "1.0.0"
#__maintainer__ = "Francisco Amato"
#__email__      = "famato@infobytesec.com"
#__status__     = "Development"

require 'java'
require "xmlrpc/client"
require "pp"


#FARADAY CONF:
RPCSERVER="http://127.0.0.1:9876/"
IMPORTVULN=1 #1 if you like to import the current vulnerabilities, or 0 if you only want to import new vulns
PLUGINVERSION="Faraday v1.0 Ruby"
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
java_import 'java.net.InetAddress'


class BurpExtender
  include IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener
    
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


    # register ourselves as a Scanner listener
    callbacks.registerScannerListener(self)
    
    # register ourselves as an extension state listener
    callbacks.registerExtensionStateListener(self)
    
  end
  
  #
  # implement IScannerListener
  #

  def newScanIssue(issue)


    host=issue.getHost()
    port=issue.getPort().to_s()
    url = issue.getUrl()
    ip=InetAddress.getByName(issue.getHttpService().getHost()).getHostAddress()
    
    @stdout.println("New scan issue host: " +host +",name:"+ issue.getIssueName() +",IP:" + ip)

    begin
      param = @server.call("devlog", "[BURP] New issue generation")

      h_id = @server.call("createAndAddHost",ip, "unknown")
      i_id = @server.call("createAndAddInterface",h_id, ip,"00:00:00:00:00:00", ip, "0.0.0.0", "0.0.0.0",[],
                          "0000:0000:0000:0000:0000:0000:0000:0000","00","0000:0000:0000:0000:0000:0000:0000:0000",
                          [],"",host)
    
      #@stdout.println("[BURP] - h_id:" + h_id +",port=" + port)

      s_id = @server.call("createAndAddServiceToInterface",h_id, i_id, issue.getProtocol(),"tcp",[port],"open")

      #Save website
      n_id = @server.call("createAndAddNoteToService",h_id,s_id,"website","")
      n2_id = @server.call("createAndAddNoteToNote",h_id,s_id,n_id,host,"")

      unless issue.getHttpMessages().nil?
        issue.getHttpMessages().each do |m|
          req= @helpers.analyzeRequest(m.getRequest())

          #TODO: Actually Get all parameters, cookies, jason, url, maybe we should get only url,get/post paramenter
          param=""
          req.getParameters().each { |p| param += p.getName()+"="+p.getValue()+","}

          # @stdout.println("createAndAddVulnWebToService,"+h_id+ s_id+ issue.getIssueName().to_s+
          #            issue.getIssueDetail().to_s+"[]"+issue.getSeverity().to_s+host+m.getUrl().to_s+m.getRequest().to_s+
          #            ",response,"+req.getMethod().to_s+",-,"+param+",url.getQuery(),"+"")
          desc=issue.getIssueDetail().to_s
          desc+="<br/>Resolution:" + issue.getIssueBackground().to_s

          v_id = @server.call("createAndAddVulnWebToService",h_id, s_id, issue.getIssueName().to_s,
                 desc,[],issue.getSeverity().to_s,host,m.getUrl().to_s,m.getRequest().to_s,
                 "response",req.getMethod().to_s,"",param,"","")
        end
      end
      
    # def createAndAddVulnWebToService(self, host_id, service_id, name, desc="", ref=[], severity="", website="", path="", request="",
    #                               response="",method="",pname="", params="",query="",category=""):

    rescue XMLRPC::FaultException => e
      puts "Error:"
      puts e.faultCode
      puts e.faultString
    end
  end

  def extensionUnloaded()

  end

end      
