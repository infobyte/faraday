#!/usr/bin/ruby
###
## Faraday Penetration Test IDE
## Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###
#__author__	= "Francisco Amato"
#__copyright__	= "Copyright (c) 2014, Infobyte LLC"
#__credits__	= ["Francisco Amato"]
#__version__	= "1.2.0"
#__maintainer__ = "Francisco Amato"
#__email__	= "famato@infobytesec.com"
#__status__	= "Development"

require 'java'
require "xmlrpc/client"
require "pp"


PLUGINVERSION="Faraday v1.2 Ruby"
#Tested: Burp Professional v1.6.09

XMLRPC::Config.module_eval do
    remove_const :ENABLE_NIL_PARSER
    const_set :ENABLE_NIL_PARSER, true
end
java_import 'burp.IBurpExtender'
java_import 'burp.ITab'
java_import 'burp.IHttpListener'
java_import 'burp.IProxyListener'
java_import 'burp.IScannerListener'
java_import 'burp.IExtensionStateListener'
java_import 'burp.IExtensionHelpers'
java_import 'burp.IContextMenuFactory'
java_import 'java.net.InetAddress'
java_import 'javax.swing.JMenuItem'
java_import 'javax.swing.JCheckBox'
java_import 'javax.swing.JPanel'
java_import 'javax.swing.GroupLayout'
java_import 'javax.swing.event.DocumentListener'

class SimpleDocumentListener

  # This is how we declare that this class implements the Java
  # DocumentListener interface in JRuby:
  include DocumentListener

  attr_accessor :behavior

  def initialize(&behavior)
    self.behavior = behavior
  end

  def changedUpdate(event);  behavior.call event; end
  def insertUpdate(event);   behavior.call event; end
  def removeUpdate(event);   behavior.call event; end

end


class BurpExtender
  include IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener,IContextMenuFactory, ITab

  #
  # implement IBurpExtender
  #

  def registerExtenderCallbacks(callbacks)

    # keep a reference to our callbacks object
    @callbacks = callbacks

    # set our extension name
    callbacks.setExtensionName(PLUGINVERSION)

    # obtain our output stream
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)

    # create the tab

    @import_current_vulns = javax.swing.JButton.new("Import current vulnerabilities")
    @import_new_vulns = javax.swing.JCheckBox.new("Import new vulnerabilities")
    @rpc_server_label = javax.swing.JLabel.new("Faraday RPC server:")
    @rpc_server = javax.swing.JTextField.new()
    @rpc_server_label.setLabelFor(@rpc_server)
    @restore_btn = javax.swing.JButton.new("Restore configuration")
    @save_btn = javax.swing.JButton.new("Save configuration")

    @rpc_server.getDocument.addDocumentListener(
	SimpleDocumentListener.new do
	    @server = XMLRPC::Client.new2(@rpc_server.getText())
    end)

    @restore_btn.addActionListener do |e|
	restoreConfig()
    end
    @save_btn.addActionListener do |e|
	saveConfig()
    end
    @import_current_vulns.addActionListener do |e|
	importVulns()
    end

    restoreConfig()

    @tab = javax.swing.JPanel.new()

    @layout = javax.swing.GroupLayout.new(@tab)
    @tab.setLayout(@layout)
    @layout.setAutoCreateGaps(true)
    @layout.setAutoCreateContainerGaps(true)
    @layout.setHorizontalGroup(
	@layout.createParallelGroup()
	    .addComponent(@import_current_vulns)
	    .addComponent(@import_new_vulns)
	    .addComponent(@rpc_server_label)
	    .addComponent(@rpc_server)
	    .addComponent(@restore_btn)
	    .addComponent(@save_btn)
    )
    @layout.setVerticalGroup(
	@layout.createSequentialGroup()
	    .addComponent(@import_current_vulns)
	    .addComponent(@import_new_vulns)
	    .addComponent(@rpc_server_label)
	    .addComponent(@rpc_server)
	    .addComponent(@restore_btn)
	    .addComponent(@save_btn)
    )
    @layout.linkSize(javax.swing.SwingConstants.VERTICAL, @import_new_vulns, @rpc_server)

    callbacks.addSuiteTab(self)

    @helpers = callbacks.getHelpers()

    @stdout.println(PLUGINVERSION + " Loaded.")
    @stdout.println("RPCServer: " + @rpc_server.getText())
    @stdout.println("Import new vulnerabilities detected: " + boolString(@callbacks.loadExtensionSetting("import_new_vulns")))
    @stdout.println("------")

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

      # Sitemap history, Proxy History, Request views, and Scanner will show menu item if selected by the user
      #@stdout.println('Menu TYPE: %s\n' % ctx)
      if ctx == 5 or ctx == 6 or ctx == 2 or ctx == 7

	  faradayMenu = JMenuItem.new("Send to Faraday", nil)

	  faradayMenu.addActionListener do |e|
	     eventScan(invocation, ctx)
	  end

	  menu.push(faradayMenu)
      end

      return menu
  end

  #

  # event click function
  #
  def eventScan(invocation, ctx)

      #Scanner click
      if ctx == 7
	invMessage = invocation.getSelectedIssues()
	invMessage.each do |m|
	  newScanIssue(m,ctx,true)
	end
      else
	#Others
	invMessage = invocation.getSelectedMessages()
	invMessage.each do |m|
	  newScanIssue(m,ctx,true)
	end
      end
  end

  #
  # implement IScannerListener
  #
  def newScanIssue(issue, ctx=nil, import=nil)

    if import == nil && @import_new_vulns.isSelected() == 0
      #ignore new issues
      return
    end

    host = issue.getHost()
    port = issue.getPort().to_s()
    url = issue.getUrl()
    resolution = ""

    begin
      ip = InetAddress.getByName(issue.getHttpService().getHost()).getHostAddress()
    rescue  Exception => e
      ip = host
    end

    if ctx == 5 or ctx == 6 or ctx == 2
      issuename="Analyzing: "
      severity="Information"
      desc="This request was manually sent using burp"
    else
      desc=issue.getIssueDetail().to_s
      desc+="<br/>Resolution:" + issue.getIssueBackground().to_s
      severity=issue.getSeverity().to_s
      issuename=issue.getIssueName().to_s
      resolution=issue.getRemediationBackground().to_s
    end

    @stdout.println("New scan issue host: " +host +",name:"+ issuename +",IP:" + ip)

    begin
      rt = @server.call("devlog", "[BURP] New issue generation")

      h_id = @server.call("createAndAddHost",ip, "unknown")
      i_id = @server.call("createAndAddInterface",h_id, ip,"00:00:00:00:00:00", ip, "0.0.0.0", "0.0.0.0",[],
			  "0000:0000:0000:0000:0000:0000:0000:0000","00","0000:0000:0000:0000:0000:0000:0000:0000",
			  [],"",host)

      s_id = @server.call("createAndAddServiceToInterface",h_id, i_id, issue.getProtocol(),"tcp",[port],"open")

      #Save website
      n_id = @server.call("createAndAddNoteToService",h_id,s_id,"website","")
      n2_id = @server.call("createAndAddNoteToNote",h_id,s_id,n_id,host,"")

      path = ""
      response = ""
      request = ""
      method = ""
      param = ""

      #Menu action
      if ctx == 5 or ctx == 6 or ctx == 2
	req = @helpers.analyzeRequest(issue.getRequest())

	param = getParam(req)
	issuename += "("+issue.getUrl().getPath()[0,20]+")"
	path = issue.getUrl().to_s
	request = issue.getRequest().to_s
	method = req.getMethod().to_s

      else #Scan event or Menu scan tab
	unless issue.getHttpMessages().nil? #issues with request #IHttpRequestResponse
	  c = 0
	  issue.getHttpMessages().each do |m|
	    if c == 0
	      req = @helpers.analyzeRequest(m.getRequest())
	      path = m.getUrl().to_s
	      request = m.getRequest().to_s
	      method = req.getMethod().to_s

	      param = getParam(req)
	    else
	      desc += "<br/>Request (" + c.to_s + "): " + m.getUrl().to_s
	    end

	    c = c + 1
	  end

	  if c == 0
	    path = issue.getUrl().to_s
	  end

	end
      end

      #createAndAddVulnWebToService(host_id, service_id, name, desc, ref, severity, resolution, website, path, request, response,method,pname, params,query,category):
      v_id = @server.call("createAndAddVulnWebToService",h_id, s_id, issuename,
	     desc,[],severity,resolution,host,path,request,
	     response,method,"",param,"","")


    rescue XMLRPC::FaultException => e
      puts "Error:"
      puts e.faultCode
      puts e.faultString
    end
  end

  def extensionUnloaded()

  end

  def getTabCaption()
      return "Faraday"
  end

  def getUiComponent()
      return @tab
  end

  #
  # convert integer to string
  #
  def boolString(value)
    if value == "0"
      return "false"
    else
      return "true"
    end
  end

  #
  # get param for one url
  #
  def getParam(value)
    param = ""
    value.getParameters().each do |p|
      #TODO: Actually Get all parameters, cookies, jason, url, maybe we should get only url,get/post parameters
      #http://portswigger.net/burp/extender/api/constant-values.html#burp.IParameter.PARAM_BODY
      param += "%s" % p.getType() + ":" + p.getName() + "=" + p.getValue() + ","
    end
    return param

  end

  def restoreConfig(e=nil)
      @import_new_vulns.setSelected(@callbacks.loadExtensionSetting("import_new_vulns") == "1")
      @rpc_server.setText(@callbacks.loadExtensionSetting("rpc_server"))
      if @rpc_server.getText().strip == ""
	  @rpc_server.setText("http://127.0.0.1:9876/")
      end

      #Connect Rpc server
      @server = XMLRPC::Client.new2(@rpc_server.getText())

      @stdout.println("Config restored.")
  end

  def saveConfig(e=nil)
      @callbacks.saveExtensionSetting("import_new_vulns", @import_new_vulns.isSelected() ? "1" : "0")
      @callbacks.saveExtensionSetting("rpc_server", @rpc_server.getText())
      @stdout.println("Config saved.")
  end


  def importVulns()
    # Get current vulnerabilities
      @stdout.println("Importing vulns.")
      rt = @server.call("devlog", "[BURP] Importing issues")
      @callbacks.getScanIssues(nil).each do |issue|
	newScanIssue(issue, 1, true)
      end
  end


end
