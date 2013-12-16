#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import pwd
import re
from cStringIO import StringIO

from model.common import ModelObject
from shell.core.history import HistoryTypeBuffer
import model.api as api

from ecma48 import strip_control_sequences 
#TODO: check from config if it is qt3 or qt4 and import the right one
from gui.qt3.pyqonsole.widget import ShellWidget
from shell.controller.qt3.session import Session
#from shell.controller.qt3.procctrl import ProcessController
from model.common import TreeWordsTries
from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

next_id = 1
#-------------------------------------------------------------------------------

#TODO: decide if we really need to inherit from ModelObject
class ShellEnvironment(ModelObject):
    """
    Shell environment is really a group of components that need to work together
    The environment is composed by:
        * a ShellWidget used in the GUI
        * a Session (which is the real shell)
        * a PluginController needed to handle all shell input and output
    The shell environment interacts with the Model Controller to add new hosts
    """
    def __init__(self, name, qapp, gui_parent, model_controller,
                 plugin_controller, close_callback=None):

        ModelObject.__init__(self)
        self._id = self.get_id()
        self.name = name

        # a reference used to add new hosts
        self._model_controller = model_controller

        # create the widget
        self.widget = ShellWidget(qapp,gui_parent,name)
        self.widget.setupLayout()

        # For safesty we don't use the user shell, we force it to bash
        progname = "/bin/bash"
        # create the session
        #Session(gui, pgm, args, term, sessionid='session-1', cwd=None):
        #self.process_controller = ProcessController()
        self.session = Session(self.widget, progname, [], "xterm", name);

        self.session.setConnect(True)
        self.session.setHistory(HistoryTypeBuffer(1000))
        self._setUpSessionSinalHandlers()

        #self.__last_user_input = None
        #self.__user_input_signal = False

        # flag that determines if output has to be ignored
        self.__ignore_process_output = False
        self.__ignore_process_output_once = False
        self.__first_process_output = True
        self.__save_output_prompt_format = False

        # determines if input is for an interactive command or not
        self.__interactive = False

        #TODO: check if we need to connect to this signal
        self.session.myconnect('done', self.close)

        # instance a new plugin controller
        self.plugin_controller = plugin_controller(self.id)

        self._initial_prompt = ""
        #self._custom_prompt_format = re.compile("\\x1B\[1;32m\[.+@.+\s.+\]>(\$|#)\s+\\x1B\[m")
        #self._custom_prompt_format = re.compile("\[.+@.+\s.+\]>(\$|#)\s+")
        self._custom_prompt_format = re.compile("\[(?P<user>.+)@(?P<host>.+):(?P<path>.+)\]>(\$|#)")
        #TODO: somewhere in the config there should be a list of regexes used to match
        # prompts. Be careful with this because if regexes are too generic they will
        # match more that is needed.
        self._generic_prompt_formats = []
        #XXX: adding this format just as a test! This should be in the config somehow
        # Also this may be is too generic to use...
        self._generic_prompt_formats.append(re.compile("^.+@.+:.+(\$|#)$"))
        
        #This is a reference to MainApplication.deleteShellEnvironment
        self._close_callback = close_callback 
        
        # flag that determines if shell environment is running
        self.__running = False
        
        #Autocomplete
        self._options=[] #only keys
        self._tname="" # last tool executed
        self._lcount=0
        self._optionsh={} #keys + help
        self.__command = ''
    def __del__(self):
        """
        When deleteing the environment we have to delete all the components
        """
        #print "ShellEnvironment __del__ called"
        del self.session
        #TODO: delete tab holding current ShellWidget
        #tabmgr = self.widget.parentWidget()
        #tabmgr.removeView(self.widget)
        #FIXME: check the __del__ method in ShellWidget
        #del self.widget
        #TODO: make sure the plugin controller correctly finishes all processes
        del self.plugin_controller

    def close(self, session, status, *args):
        #TODO: por alguna razon queda colgado un QSocketNotifier
        # QSocketNotifier: invalid socket 17 and type 'Read', disabling...
        # y eso cuelga la aplicacion
        api.devlog("ShellEnvironment close was called - session = %r, status = %r , *args = %r" % (session, status, args))
        if self._close_callback is not None:
            self._close_callback(self.name, self)
        else:
            api.devlog("close was call but callback is not set")

    #def setCloseCallback(self, ref):
    #    self._close_callback = ref

    def get_id(self):
        global next_id
        # just to make sure each env has a differente id because names can be the same
        id = next_id
        next_id += 1
        return id

    def run(self):
        self.session.run()
        self.__running = True
        #self.plugin_controller.run()

    def _setUpSessionSinalHandlers(self):
        """
        Connects some signal handlers to different signals emmited inside shell
        emulation and pty.
        These signals are used to handle user input and child process output
        """
        #IMPORTANT ABOUT USER INPUT AND PROCESS OUPUT (Session class)
        #PtyProcess in method dataReceived gets the child output
        #in method sendBytes it has the user input
        #
        #Emulation in method sendString also has the user input
        #also check method onKeyPressed to identify when an ENTER key is pressed
        #
        #
        #OUTPUT
        # emulation onRcvBlock le llega la salida del proceso
        # self.myconnect('receivedStdout', self.dataReceived)
        # Este se llama desde childOutput en pty_
        #    self.myemit("receivedStdout", (fdno, lenlist))
        #
        # self.myemit('block_in', (buf,)) <--- se llama desde dataReceived
        # self.sh.myconnect('block_in', self.em.onRcvBlock)
        #
        #INPUT
        # self.myemit("sndBlock", (string,))
        # self.em.myconnect('sndBlock', self.sh.sendBytes)
        #
        # otra opcion es agregar una senal propia en los metodos sendString
        # o en onKeyPressed de emuVt102

        # connect signals to handle shell I/O
        self.session.sh.myconnect('processOutput', self.processOutputHandler)

        #XXX: nasty hack to be able to send a return value
        # Using myconnect and emitting singals won't allow us to return a value
        self.session.em.sendENTER = self.processUserInputBuffer
        self.widget.myconnect('ignoreShellWidgetResize', self.ignoreDueResize)
        
        #handle ctrl+space
        self.session.em.sendCTRLSPACE = self.processCtrlSpace
        self.session.em.sendRIGHT = self.processMove
        self.session.em.sendLEFT = self.processMove
        self.session.em.sendUP = self.processMove
        self.session.em.sendDOWN = self.processMove
        


    #---------------------------------------------------------------------------
    # methods to handle signals for shell I/O
    # these methods must be async to avoid blocking shell
    # XXX: signalable object is used.. and it is not really async
    #---------------------------------------------------------------------------


    def replaceWord(self, source, dest, output):
        #matchesWord = re.findall("(\x1b+\x1b?.*?%s\x1b?)"%source, output)
        matchesWord = re.findall("(\x1b\[01;34m127.0.0.1\x1b)", output)

        for w in matchesWord:
            output = output.replace(w, dest)

        return output

    def highligthword(self, w, output):
        highlighted_word = "\x1b[02;44m%s\x1b[0m" % w
        output = self.replaceWord(w, highlighted_word, output)
        return output

    def processOutputHandler(self, output):
        """
        This method is called when processOutput signal is emitted
        It sends the process output to the plugin controller so it can
        pass it to the corresponding plugin
        """
        # the output comes with escape chars for example to show things with colors
        # those escape chars are messing the text and plugins may not handle that
        # correctly.
        #TODO: implement some way of removing the escape sequences

        # if we get the output from the screen image we have some issues when the
        # output is longer than the actual size and scrolls the window
        #TODO: check how to handle the window scrolling

        #output = self.session.em.getLastOutputFromScreenImage(1)
        #api.devlog("-"*50)
        #api.devlog("processOutputHandler called - output =\n%r" % self.session.em.getLastOutputFromScreenImage(1))
        #api.devlog("processOutputHandler called - hist lines = %r" % self.session.em._scr.getHistLines())
        #api.devlog("-"*50)

        #TODO: is this really needed??? (to save first prompt output)
        if self.__first_process_output:
            # save the output as prompt
            #api.devlog("Saving prompt for the first time\n\tPROMPT: %r" % output)
            # then mark flag because it won't be the first anymore
            self._initial_prompt = output.strip()
            self.__first_process_output = False
            # after getting first output which is the default prompt
            # we change it and clear screen
            self.__setCurrentShellPromptFormat()
            self.session.updateLastUserInputLine()
            return

        if self.__save_output_prompt_format:
            # means the output is the PS1 format and we have to store it
            # The output is the result of running "echo $PS1" so 2 lines are
            # generated: one with the actual value of PS1 and one more
            # that is the prompt just because the echo finished
            # So we have to keep the first line only
            self._initial_prompt = ouput.splitlines()[0].strip()
            self.__save_output_prompt_format = False


        #strip_control_sequences(output)


        #print "AAAAAAAAAAAAAaaa: ", repr(output)
        #for word in wordsFound:
        #    output = self.highligthword(word, output)


        # check if output has to be ignored
        if not self.__ignore_process_output and not self.__ignore_process_output_once:
            api.devlog("processOutputHandler (PROCESSED):\n%r" % output)

            command_finished, output = self.check_command_end(output)

            #IMPORTANT: if no plugin was selected to process this output
            # we don't need to send to controller
            if self.plugin_controller.getActivePluginStatus():
                # always send all output to the plugin controller
                self.plugin_controller.storeCommandOutput(output)
                # if command ended we notify the plugin
                if command_finished:
                    api.devlog("calling plugin_controller.onCommandFinished()")
                    self.plugin_controller.onCommandFinished()
            else:
                api.devlog("<<< no active plugin...IGNORING OUTPUT >>>")

        else:
            #if re.search("export PS1",output) == None:
            #    self.__command += output

            #if re.search("export PS1",output) == None:
            #    self.__command += output
            #
            #if self.__command != "":
            #    api.devlog("processOutputHandler (Allcommand): (%s)" % self.__command)
            #    
            #    #TODO: hacer un regex inicial, y verificar si es el lugar exacto para poner esto.
            #    #TODO: No soporta el backspace o caracteres especiales
            #    #TODO: Recorrer todo no es performante, hay que revisar
            #    for h in self._model_controller._hosts.itervalues():
            #        if re.search(self.__command,h.name,flags=re.IGNORECASE):
            #            api.devlog("Host name found: " + h.name + " id ("+h.id+")");
            #        for o in h.getAllInterfaces():
            #            if re.search(self.__command,o.name,flags=re.IGNORECASE):
            #                api.devlog("Host name found: " + h.name + " id ("+h.id+") - Interface ("+o.name+") id ("+o.id+")");
            #        for o in h.getAllApplications():
            #            if re.search(self.__command,o.name,flags=re.IGNORECASE):
            #                api.devlog("Host name found: " + h.name + " id ("+h.id+") - Application ("+o.name+") id ("+o.id+")");
                    
                
            api.devlog("processOutputHandler (IGNORED by flags): \n%r" % output)
            #api.devlog("self.__ignore_process_output_once = %s" % self.__ignore_process_output_once)
            #api.devlog("self.__ignore_process_output = %s" % self.__ignore_process_output)
            self.__ignore_process_output_once = False


        



    def processMove(self):
        """
        this method is called when up/down/left/right
        """
        
        if not self.__interactive:
            self._options=[]
            self._optionsh={}
            self._tname = ""
            
    def processCtrlSpace(self):
        """
        this method is called when the Ctrl+Space is pressed
        """
        if not self.__interactive:
            # get the complete user input from screen image (this is done so we don't
            # have to worry about handling any key)
            user_input = self.session.em.getLastOutputFromScreenImage(get_spaces=True)
            # parse input to get the prompt and command in separated parts
            
            prompt, username, current_path, command_string, command_len = self.__parseUserInput(user_input,get_spaces=True)
            api.devlog("processCtrlSpace info("+user_input+")("+command_string+")")
            api.devlog("-"*60)
            api.devlog("CTRL + SPACE \nprompt = %r\ncommand = %r" % (prompt, command_string))
            api.devlog("self.__interactive = %s" % self.__interactive )
            api.devlog("-"*60)
            
            
            words=command_string.split(" ")
            #words2=command_string.split(" ")
            cword=words[len(words)-1] #obtengo la ultima palabra
            #words.remove(cword) #elimino la ultima palabra
            options=[]
            search=0
            mindex=0
            
            try: # si encuentra la palabra significa que se encuentra en una interaccion
                mindex = self._options.index(cword)
                #api.devlog("El tname es:" + self._tname)
                # Si no es la misma herramienta o cambio la cantidad de palabra significa que tengo que empezar de nuevo
                if (self._tname != words[1] and self._tname != "") or (self._lcount != len(words)): 
                    mindex = -1
            except ValueError:
                mindex = -1

            if mindex == -1: # si no la encuentra inicia de nuevo.
                self._options=[]
                self._optionsh={}
                search=1
            else:
                options=self._options                    
            
            #Guardo la cantidad palabras para comparar despues
            self._lcount = len(words)
            
            #save first command
            if len(words) >2:
                self._tname = words[1] #guardo el nombre de la tool
            else:
                self._tname = ""

            
            if search ==1 and cword !="":
                #Busqueda de Hosts (ignore si el comando que escribi es blanco)
                for h in self._model_controller._hosts.itervalues():
                    if re.search(str("^"+cword),h.name,flags=re.IGNORECASE):
                        if len(options) == 0:
                            options.append(cword)
                        api.devlog("Host name found: " + h.name + " id ("+h.id+")");
                        options.append(h.name)
                    #Busqueda de Hostname dentro de las interfaces
                    for i in h.getAllInterfaces():
                        for hostname in i.getHostnames():                            
                            if re.search(str("^"+cword),hostname,flags=re.IGNORECASE):
                                if len(options) == 0:
                                    options.append(cword)
                                api.devlog("Hostname found: " + hostname + " id ("+i.id+")");
                                options.append(hostname)

                self._options = options
            
            new_options={}
            api.devlog("Cantidad de _options" + str(len(self._options)))
            
            #Si no se encontro nada, busco opciones en el plugin
            if len(self._options) == 0:
                #try:
                if 1==1:
                    #Llamo al controller para ver si hay algun plugin que pueda dar opciones
                    #Devuelve un dict del estilo 'option' : 'help de la option'
                    new_options = self.plugin_controller.getPluginAutocompleteOptions(prompt, username,
                                                                         current_path,
                                                                         command_string,
                                                                         self.__interactive)
                    
                    
                    if new_options != None: 
                        if len(new_options) >= 1: #Si encontro plugin que maneje y  trae opciones hago iteracciones.
                            api.devlog("Options de plugin encontradas: ("+str(len(new_options))+") valores ("+str(new_options)+")")
                            options = [cword]+new_options.keys() #Guardo las opciones (agrego la word inicial)
                            self._options = options 
                            self._optionsh = new_options
                                
                            api.devlog("getPluginAutocompleteOptions: %r" % user_input)
                            api.devlog("new_options:" + str(options))
                if 1==2:
                #except Exception:
                    api.devlog("Exception: Plugin")
                    # if anything in the plugins fails and raises an exception we continue wihout doing anything
                    new_cmd = None                
            
            # Recorro las opciones disponibles
            #TODO: Reemplazar esto por una ventana desplegable o 
            i=0
            newword=""
            if len(options) > 1: # Reemplazar solo si hay opciones
                for w in options:
                    #api.devlog("Por la palabra ("+ w +") (" + str(i)+") la palabra(" + cword+")")
                    if cword==w:
                        if len(options) > i+1:
                            newword=options[i+1]
                            #api.devlog("La encontre next ("+ newword +") (" + str(i)+")"+ str(options) )
                        else:
                            newword=options[0]
                            #api.devlog("La encontre last ("+ newword +") (" + str(i)+")"+ str(options) )
                            #newword="-h"
                    i+=1
                    
                if self._optionsh.has_key(newword):
                    #TODO: reemplazar esto por un help distinto no usar el devlog
                    api.showPopup( newword + " :" + self._optionsh[newword])
                    #api.devlog("pluginhelp: " + newword + " :" + self._optionsh[newword])
                
                #Hago el cambio en la shell
                self.session.sh.sendBytes("\b" * len(cword) +  newword)

    def processUserInputBuffer(self):
        """
        this method is called when the ENTER is pressed
        It processes the user input buffer and then it clears it for future
        if a new command is returned by a plugin this is returned to the caller
        (which is onKeyPress in module emuVt102)
        """

        command_string=""
        command_len = 0
        if not self.__interactive:
            # get the complete user input from screen image (this is done so we don't
            # have to worry about handling any key)
            user_input = self.session.em.getLastOutputFromScreenImage(get_full_content=True)
            api.devlog("user_input parsed from screen(0) = %s" % user_input)
            # parse input to get the prompt and command in separated parts
            prompt, username, current_path, command_string, command_len = self.__parseUserInput(user_input)
            
            api.devlog("user_input parsed from screen(1) =%s" % self.session.em.getLastOutputFromScreenImage(index=1, get_full_content=True))

            # we send the buffer to the plugin controller to determine
            # if there is a plugin suitable to handle it
            api.devlog("-"*60)
            api.devlog("about to call plugin controller\nprompt = %r\ncommand = %r" % (prompt, command_string))
            api.devlog("self.__interactive = %s" % self.__interactive )
            api.devlog("-"*60)
            # when calling the plugin, the command string may be changed
            # if the configuration allows this we send it instead of the typed one
            #TODO: validate config to allow this

            try:
                new_cmd = self.plugin_controller.processCommandInput(prompt, username,
                                                                     current_path,
                                                                     command_string,
                                                                     self.__interactive)
                
                # we set it to interactive until we make sure the command has finished
                # this check is done in processOutputHandler
                self.__interactive = True
                api.devlog("processUserInputBuffer: %r" % user_input)
                api.devlog("new_cmd: %r" % new_cmd)
            except Exception, e:
                # if anything in the plugins fails and raises an exception we continue wihout doing anything
                api.devlog("ERROR: processCommandString")
                api.devlog(e)
                new_cmd = None

            if new_cmd is None:
                # the output MUST BE processed
                self.__ignore_process_output = False
                self.__ignore_process_output_once = False
            else:
                # means the plugin changed command and we are going to send
                # ALT + r to delete current line. That produces an empty output
                # which has to be ignored
                    
                self.__ignore_process_output_once = True
                self.__ignore_process_output = False
        else:
            api.devlog("IGNORING BECAUSE INTERACTIVE FLAG WAS SET")
            new_cmd = None
            

        return new_cmd,command_string,command_len

    def ignoreDueResize(self):
        self.__ignore_process_output = True


    def __parseUserInput(self, user_input="", get_spaces=False):
        """
        parses the user input buffer and returns the following values:
            * current user prompt
            * current username
            * current path
            * command or text after prompt
        """
        username = ""
        hostname = ""
        current_path = ""
        usr_prompt = ""
        usr_command = ""
        raw_command = ""

        match = self._custom_prompt_format.search(user_input)
        if match is not None:
            username = match.group("user")
            hostname = match.group("host")
            current_path = os.path.expanduser(match.group("path"))
            usr_prompt = user_input[:match.end()].strip()
            raw_command = user_input[match.end():]
            if get_spaces == False:
                usr_command = raw_command.strip()
            else:
                usr_command = raw_command
        else:
            # means there was no prompt and theres only user input
            usr_command = user_input 

        return usr_prompt, username, current_path, usr_command, len(raw_command)

    def __setCurrentShellPromptFormat(self):
        # this is done to be able to detect the prompt later
        # Since we defined the prompt format we know how to parse it
        # The prompt format must not contain color escape chars or it'll mess up the output
        self.session.set_shell_ps1("[\\u@\\h:\\w]>\\$ ")

    def __getCurrentShellPromptFormat(self):
        """
        this gets the current PS1 environment variable
        of the current shell created.
        This is async because a command is sent and
        the output is retrieved later.
        """
        self.__save_output_prompt_format = True
        self.session.get_shell_ps1()


    def __matchesCustomPrompt(self, txt):
        """
        checks if the current text matches our custom prompt format
        and returns true in that case, false otherwise
        """
        if not self._custom_prompt_format:
            api.devlog("prompt format (PS1) is not defined.\nThis may cause unexpected results...")
            return False

        txt = txt.strip()
        m = self._custom_prompt_format.search(txt)
        return (m is not None)
        
        #XXX: this code below checked that the match was the last part of the text
        #if m is not None:
        #    if len(txt) == m.end():
        #       return True
        #return False
    
    def __matchGenericPrompt(self, txt):
        """
        checks if the current text matches against a list of
        generic prompt formats defined in the configuration
        and returns true in that case, false otherwise.
        This is used because if a prompt is detected it may be because a connection
        was established with a remote host.
        """
        if not self._generic_prompt_formats:
            api.devlog("There isn't any generic prompt format defined")
            return False
        
        txt = txt.strip()
        # Should we use match instead of search?
        for r in self._generic_prompt_formats:
            m = r.search(txt)
            if m is not None:
                return True
        return False
        
        
    def check_command_end(self, output):
        """
        Checks if the command finished by checking if the last line of the ouput
        is just our shell custom prompt.
        It also checks if a generic prompt is detected as the last line, which
        could mean that the commmand may have resulted in a remote connection
        to another host or device.
        This method returns 2 values: first a boolean flag that determines if
        command ended and then the full command output.
        """
        # We check if the last line in the output is just our modified shell prompt...
        # This would mean the command ended and we notify the plugin then
        api.devlog("check_command_end called...\noutput received = %r" % output)
        output_lines = output.splitlines()
        last_line = output_lines[-1].strip()
        api.devlog("about to test match with line %r" % last_line)
        command_finished = self.__matchesCustomPrompt(last_line)
        #command_finished = self.__matchesCustomPrompt(last_line.split()[0])
        if command_finished:
            # if we found this prompt then it means the command ended
            # we remove that line from output to send it
            api.devlog("command finished. Removing last line from output because it is just the prompt")
            output_lines.pop(-1)
            output = "\n".join(output_lines)
            # if command finished we need to ignore further output. It will be user input
            self.__ignore_process_output = True
            self.__interactive = False
            self.session.updateLastUserInputLine()
        else:
            # if we are here means that last line of the output is not our custom
            # shell prompt, but we need to check if a generic prompt is there
            # which means a remote connection may have been established
            if self.__matchGenericPrompt(last_line):
                api.devlog("A generic prompt format matched the last line of the command ouput")
                #TODO: define what to do in this case
        
        return command_finished, output

    def terminate(self):
        if self.__running:
            self.__running = False
            self.session.terminate()
#-------------------------------------------------------------------------------
