# Copyright (c) 2005-2006 LOGILAB S.A. (Paris, FRANCE).
# Copyright (c) 2005-2006 CEA Grenoble
# http://www.logilab.fr/ -- mailto:contact@logilab.fr
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the CECILL license, available at
# http://www.inria.fr/valorisation/logiciels/Licence.CeCILL-V2.pdf
#
"""Provide the Emulation class.

This class acts as the controler between the Screen class (Model) and
Widget class (View). As Widget uses Qt, Emulation also depends on Qt.
But it is very easy to use another toolkit.

A note on refreshing

   Although the modifications to the current screen image could immediately
   be propagated via `Widget' to the graphical surface, we have chosen
   another way here.

   The reason for doing so is twofold.

   First, experiments show that directly displaying the operation results
   in slowing down the overall performance of emulations. Displaying
   individual characters using X11 creates a lot of overhead.

   Second, by using the following refreshing method, the screen operations
   can be completely separated from the displaying. This greatly simplifies
   the programmer's task of coding and maintaining the screen operations,
   since one need not worry about differential modifications on the
   display affecting the operation of concern.

   We use a refreshing algorithm here that has been adoped from rxvt/kvt.

   By this, refreshing is driven by a timer, which is (re)started whenever
   a new bunch of data to be interpreted by the emulation arives at `onRcvBlock'.
   As soon as no more data arrive for `BULK_TIMEOUT' milliseconds, we trigger
   refresh. This rule suits both bulk display operation as done by curses as
   well as individual characters typed.
   (BULK_TIMEOUT < 1000 / max characters received from keyboard per second).

   Additionally, we trigger refreshing by newlines comming in to make visual
   snapshots of lists as produced by `cat', `ls' and likely programs, thereby
   producing the illusion of a permanent and immediate display operation.

   As a sort of catch-all needed for cases where none of the above
   conditions catch, the screen refresh is also triggered by a count
   of incoming bulks (`bulk_incnt').

Based on the konsole code from Lars Doelle.

@author: Lars Doelle
@author: Benjamin Longuet
@author: Frederic Mantegazza
@author: Cyrille Boullier
@author: Sylvain Thenault
@copyright: 2003, 2005, 2006
@organization: CEA-Grenoble
@organization: Logilab
@license: CECILL
"""

__revision__ = '$Id: emulation.py,v 1.25 2006-02-15 10:24:01 alf Exp $'

import qt
import shell.core.signalable as signalable
import keytrans
import re
from shell.core.screen import Screen
from model.common import TreeWordsTries
import model.api

NOTIFYNORMAL = 0
NOTIFYBELL = 1
NOTIFYACTIVITY = 2
NOTIFYSILENCE = 3

BULK_TIMEOUT = 20


class Emulation(signalable.Signalable, qt.QObject):
    """This class acts as the controler between the Screen class (Model) and
    Widget class (View). It's actually a common abstract base class for
    different terminal implementations, and so should be subclassed.

    It is responsible to scan the escapes sequences of the terminal
    emulation and to map it to their corresponding semantic complements.
    Thus this module knows mainly about decoding escapes sequences and
    is a stateless device w.r.t. the semantics.

    It is also responsible to refresh the Widget by certain rules.
    """
    def __init__(self, gui):
        super(Emulation, self).__init__()
        self._gui = gui
        # 0 = primary, 1 = alternate
        self._screen = [Screen(self._gui.lines, self._gui.columns),
                        Screen(self._gui.lines, self._gui.columns)]
        self._scr = self._screen[0]
        # communicate with widget
        self._connected = False
        # codec
        self._codec = None
        self._decoder = None
        # key translator
        self._key_trans = None
        self.setKeymap(0)
        # bulk handling
        self._bulk_timer = qt.QTimer(self)
        self._bulk_nl_cnt = 0 # bulk new line counter
        self._bulk_in_cnt = 0 # bulk counter
        self._bulk_timer.connect(self._bulk_timer, qt.SIGNAL("timeout()"),
                                 self._showBulk)
        gui.myconnect("changedImageSizeSignal", self.onImageSizeChange)
        gui.myconnect("changedHistoryCursor", self.onHistoryCursorChange)
        gui.myconnect("keyPressedSignal", self.onKeyPress)
        gui.myconnect("beginSelectionSignal", self.onSelectionBegin)
        gui.myconnect("extendSelectionSignal", self.onSelectionExtend)
        gui.myconnect("endSelectionSignal", self.setSelection)
        gui.myconnect("clearSelectionSignal", self.clearSelection)
        gui.myconnect("isBusySelecting", self.isBusySelecting)
        gui.myconnect("testIsSelected", self.testIsSelected)
        gui.myconnect("onDoubleClickSignal", self.onDoubleClick)


        self._lasted_highlighted = []

        self.debug=0
        self.history_h = []
        self._save_last_cursor_pos = False
        # pos 0 will be used for user input grabbing
        # pos 1 will be used for process output grabbing
        self._last_cu_x = [0, 0]
        self._last_cu_y = [0, 0]

    def __del__(self):
        self._bulk_timer.stop()

    def _setScreen(self, n):
        """change between primary and alternate screen"""
        old = self._scr
        self._scr = self._screen[n]
        if not self._scr is old:
            self._scr.clearSelection()
            old.busy_selecting = False

    def setHistory(self, history_type):
        self._screen[0].setScroll(history_type)
        if self._connected:
            self._showBulk()

    def history(self):
        return self._screen[0].getScroll()

    def setKeymap(self, no):
        self._key_trans = keytrans.find(no)

    def keymap(self):
        return self._key_trans


    # Interpreting Codes
    # This section deals with decoding the incoming character stream.
    # Decoding means here, that the stream is first seperated into `tokens'
    # which are then mapped to a `meaning' provided as operations by the
    # `Screen' class.

    def onRcvChar(self, c):
        """process application unicode input to terminal"""
        raise NotImplementedError()

    def setMode(self):
        raise NotImplementedError()

    def resetMode(self):
        raise NotImplementedError()

    def sendString(self, string, clear_line = False, old_len=0):
        if clear_line:
            # we send backspace keys to delete the whole current output in the screen
            # this way we are deleteing the current command in the screen to send the new one
            backspace_amount = self.getCurrentOutputLen()
            if backspace_amount:
                #self.myemit("sndBlock", ("\010"*backspace_amount,))
                #Fix: Error consola modificacion usign left arrow
                self.myemit("sndBlock", ("\x1b\x5b\x43"*old_len,))
                self.myemit("sndBlock", ("\010"*old_len,))
                
            
            # now we send the new command
            self.myemit("sndBlock", (string,))
            # now we need to put an ENTER because the clear line happens when pressing that
            string = "\r"
        else:
            self.myemit("sndBlock", (string,))

    def sendENTER(self):
        #XXX: this method will be changed with a reference to another method
        # this is a nasty hack... we'd better change it...
        pass
    def sendCTRLSPACE(self):
        #XXX: this method will be changed with a reference to another method
        # this is a nasty hack... we'd better change it...
        pass
    def sendLEFT(self):
        #XXX: this method will be changed with a reference to another method
        # this is a nasty hack... we'd better change it...
        pass
    def sendRIGHT(self):
        #XXX: this method will be changed with a reference to another method
        # this is a nasty hack... we'd better change it...
        pass
    def sendUP(self):
        #XXX: this method will be changed with a reference to another method
        # this is a nasty hack... we'd better change it...
        pass
    def sendDOWN(self):
        #XXX: this method will be changed with a reference to another method
        # this is a nasty hack... we'd better change it...
        pass
    
    # Keyboard handling
    def onKeyPress(self, ev):
        """char received from the gui"""
        raise NotImplementedError()

    def onRcvBlock(self, block):
        self.myemit("notifySessionState", (NOTIFYACTIVITY,))
        self._bulkStart()
        self._bulk_in_cnt += 1
        for c in block:
            result = self._decoder.toUnicode(c , 1)
            for char in result:
                self.onRcvChar(char.at(0).unicode())
            if c == '\n':
                self._bulkNewLine()
        self._bulkEnd()



    def __getImageLine(self, line_number):
        image, wrapped = self._scr.getCookedImage() # Get the image
        return "".join([c.c for c in image[line_number]])

    def _getWordOnPosition(self, start_xy, end_xy):
        start_x, start_y = start_xy
        end_x, end_y = end_xy

        line = self.__getImageLine(start_y)
        if start_x > end_x:
            word = line[start_x:]
        else:
            word = line[start_x:end_x+1]

        return word
        

    def onDoubleClick(self, start_word_xy, end_word_xy):
        word = self._getWordOnPosition(start_word_xy, end_word_xy)
        treeWordsTries = TreeWordsTries()
        self._gui.select_on_tree( word )

    def onSelectionBegin(self, x, y):
        if self._connected:
            self._scr.setSelBeginXY(x, y)
            self._showBulk()

    def onSelectionExtend(self, x, y):
        if self._connected:
            self._scr.setSelExtendXY(x, y)
            self._showBulk()

    def setSelection(self, preserve_line_break):
        if self._connected:
            text = self._scr.getSelText(preserve_line_break)
            if text is not None:
                self._gui.setSelection(text)

    def isBusySelecting(self, busy):
        if self._connected:
            self._scr.busy_selecting = busy

    def testIsSelected(self, x, y, ref):
        if self._connected:
            ref[0] = self._scr.testIsSelected(x, y)

    def clearSelection(self):
        if self._connected:
            self._scr.clearSelection()
            self._showBulk()

    def setConnect(self, c):
        self._connected = c
        if self._connected:
            self.onImageSizeChange(self._gui.lines, self._gui.columns)
            self._showBulk()
        else:
            self._scr.clearSelection()

    def onImageSizeChange(self, lines, columns):
        """Triggered by image size change of the TEWidget `gui'.

        This event is simply propagated to the attached screens
        and to the related serial line.
        """
        if not self._connected:
            return
        #print 'emulation.onImageSizeChange', lines, columns
        self._screen[0].resizeImage(lines, columns)
        self._screen[1].resizeImage(lines, columns)
        self._showBulk()
        # Propagate event to serial line
        self.myemit("imageSizeChanged", (lines, columns))

    def onHistoryCursorChange(self, cursor):
        if self._connected:
            self._scr.hist_cursor = cursor
            self._showBulk()

    def _setCodec(self, c):
        """coded number, 0=locale, 1=utf8"""
        if c:
            self._codec = qt.QTextCodec.codecForName("utf8")
        else:
            self._codec = qt.QTextCodec.codecForLocale()
        self._decoder = self._codec.makeDecoder()

    def _setColumns(self, columns):
        # FIXME This goes strange ways
        # Can we put this straight or explain it at least?
        # XXX moreover no one is connected to this signal...
        self.myemit("changeColumns", (columns,))

    def _bulkNewLine(self):
        self._bulk_nl_cnt += 1
        self._bulk_in_cnt = 0  # Reset bulk counter since 'nl' rule applies

    def dump_all_screen(self):
        screen_lines = []    
        image, wrapped = self._scr.getCookedImage() # Get the image
        self._gui.setLineWrapped(wrapped)
        buf = self.getLastOutputFromScreenImage(1, get_full_content = True)
        for y in xrange(self._scr.lines):
            line = "".join([c.c for c in image[y]])                
            screen_lines.append(line)
        return screen_lines

    def _showBulk(self):
        self._bulk_nl_cnt = 0
        self._bulk_in_cnt = 0
        found = False

        GRAY_COLOR = 1
        RED_COLOR = 3
        treeWordsTries = TreeWordsTries()
        
        if self._connected:
            image, wrapped = self._scr.getCookedImage() # Get the image
            self._gui.setLineWrapped(wrapped)
 
            screen_lines = self.dump_all_screen()

            for c, f in self._lasted_highlighted:
                self._scr.setBackgroundColor(c, f, 0)


            image, wrapped = self._scr.getCookedImage() # Get the image
            self._gui.setLineWrapped(wrapped)

            self._lasted_highlighted = []
            for y_position in xrange(len(screen_lines)):
                l = screen_lines[y_position]
                c_letters = 0
                for w in l.split(' '):
                    if not w:
                        c_letters += 1
                        continue

                    n_w, deleted_begin, deleted_end = self.__clean_word(w)
                    wordsFound = treeWordsTries.isInTries(n_w)

                    if wordsFound:
                        comienzo = [c_letters + deleted_begin, y_position]
                        fin =  [c_letters + deleted_begin + len(n_w) -1, y_position]
                        self._lasted_highlighted.append((comienzo, fin))
                        self._scr.setBackgroundColor(comienzo, fin, RED_COLOR)

                        found = True
                    c_letters += len(w)+1
                    
            
            if found:
                image, wrapped = self._scr.getCookedImage() # Get the image
                self._gui.setLineWrapped(wrapped)

            self._gui.setImage(image, self._scr.lines, self._scr.columns) #  Actual refresh
            self._gui.setCursorPos(self._scr.getCursorX(), self._scr.getCursorY())
            # FIXME: Check that we do not trigger other draw event here
            
            self._gui.setScroll(self._scr.hist_cursor, self._scr.getHistLines())
            #print "about to emit processOutput signal inside _showBulk"
            #buf = self.getLastOutputFromScreenImage(1)
            #print "buf = ", buf
            #self.myemit('processOutput', (buf,)) # signal to pass it to plugins
            self.updateLastCursorPos()
            self.updateLastCursorPos(True, 1)

            #self._last_cu_x = [self._scr.getCursorX(), self._scr.getCursorX()]
            #self._last_cu_y = [self._scr.getCursorY(),self._scr.getCursorY()]


    def __remove_chars(self, w, chars):
        idx = 0
        for c in w:
            if c in chars:
                idx += 1
                continue

            break
        #print "REMOVE CHARS: ", w[idx:]
        return w[idx:], idx


    def __clean_word(self, w):
        """
            Clean some puntuation simbol staring or ending the word.
            return word, begin offset, end offset
        """
        import string
        VALID_PUNCTUATION = '_'
        to_remove = string.punctuation

        #remove the valid punctuation from the invalid punctuacion list
        for v in VALID_PUNCTUATION:
            to_remove = to_remove.replace(v, "")

        original_word = w

        w, deleted_from_begin = self.__remove_chars(w, to_remove)
        w, deleted_from_end = self.__remove_chars(w[::-1], to_remove)


        return w[::-1], deleted_from_begin, deleted_from_end

    def _bulkStart(self):
        if self._bulk_timer.isActive():
            self._bulk_timer.stop()

    def _bulkEnd(self):
        if self._bulk_nl_cnt > self._gui.lines or self._bulk_in_cnt > 20:
            self._showBulk()
        else:
            self._bulk_timer.start(BULK_TIMEOUT, True)
    
    def getCurrentOutputLen(self):
        """
        This method return the length of the current output in the screen.
        This can be used to determine how long a current command typed by
        the user is and then exactly delete it.
        """
        width = self._gui.columns
        cu_x = self._scr.getCursorX()
        cu_y = self._scr.getCursorY()
        return width * (cu_y-self._last_cu_y[0]) + cu_x

    def getLastOutputFromScreenImage(self, index=0, get_full_content=False, get_spaces=False):
        """
        Gets the text from the screen image that is located from
        last cursor x,y value to the actual cursor x,y value
        Last cursor coordinates are updated in _showBulk method that
        shows the process output
        The parameter "index" is used to determine if the output is retrieved
        as if it was user input (index=0) or process output (index=1).
        If get_full_content flag is True we don't get the last line only up to the
        current x position but the complete line.
        """
        # image is a matrix with Ca (characters) for each x,y coordinate in the screen
        image, wrapped = self._scr.getCookedImage() # Get the image
        cu_x = self._scr.getCursorX()
        cu_y = self._scr.getCursorY()
        
        
        #print "getLastOutputFromScreenImage - len(image) = %d - len(wrapped) = %d" % (len(image), len(wrapped))
        #print "getLastOutputFromScreenImage - index = %d - cu_x = %d - cu_y = %d - last_x = %d - last_y = %d" %\
        #(index, cu_x, cu_y, self._last_cu_x[index], self._last_cu_y[index])
        
        #self.__debug_dump_screen()
        #self.__debug_dump_screen(1)
        
        # TODO: check how to handle scrolling if the current cu_y is less than the saved cu_y
        # TODO: another problem could be that the current y position is not the real "last line"
        # of the user input. If ENTER is pressed and the current y is not the last line the shell
        # will be getting the complete user input but this method won't be getting the same
        lines = []
        # there is a special case where last_cu_y could be greater than cu_y and in such cases we must
        # swap values to get the text correctly
        if self._last_cu_y[index] > cu_y: # swap values
            self._last_cu_y[index], cu_y = cu_y, self._last_cu_y[index]
        elif self._last_cu_y[index] == cu_y:
            # if these values are the same we need to check if the previous line is wrapped
            # and take that line too. So we go backwards checking for wrapped lines and update
            # the value of the last_cu_y to the smallest wrapped line
            for y in xrange(cu_y-1, -1, -1):
                if wrapped[y]:  
                    self._last_cu_y[index] = y
                else:
                    break # if we find a line that is now wrapped we just stop searching
            
        for y in xrange(self._last_cu_y[index], cu_y+1):
            #XXX: this code here is commented because it was used to skip the prompt
            #if y == self._last_cu_y[index]:
            #    line = "".join([c.c for c in image[y][self._last_cu_x[index]:]])
            if y == cu_y and not get_full_content:
                # this means that the line que are processing is the current line so we
                # get everything until the current x position.
                line = "".join([c.c for c in image[y][:cu_x]])
            else:
                line = "".join([c.c for c in image[y]])

            if index: 
                line = line.rstrip()

            lines.append(line)

        join_char = "\n" if index else ""
        result = join_char.join(lines)
        if get_spaces:
            return result
        else:
            return result.strip()

    def updateLastCursorPos(self, flag=False, index=0):
        if self._save_last_cursor_pos or index:
#            print "updateLastCursorPos - saving last cursor pos with index ", index
#            print "updateLastCursorPos - (BEFORE) last x = %d - last y = %d" % (self._last_cu_x[index], self._last_cu_y[index])
            self._last_cu_x[index] = self._scr.getCursorX()
            self._last_cu_y[index] = self._scr.getCursorY()
            self._save_last_cursor_pos = False
#            print "updateLastCursorPos - (AFTER) last x = %d - last y = %d" % (self._last_cu_x[index], self._last_cu_y[index])
        if not index:
            self._save_last_cursor_pos = flag
            
    def __debug_dump_screen(self, index=0):
        image, wrapped = self._scr.getCookedImage() # Get the image
        
        model.api.devlog("-"*10, " image[%d] " % index, "-"*10)

        for y in xrange(len(image)):
            line = "".join([c.c for c in image[y]])
            model.api.devlog("%d | %s |" % (y, line))
        
        model.api.devlog("-"*30)
        model.api.devlog("")
        model.api.devlog("-"*10, " wrapped[%d] " % index, "-"*10)

        for y in xrange(len(image)):
            #line = "".join([c.c for c in wrapped[y]])
            model.api.devlog("%d | %s |" % (y, wrapped[y]))
        
        model.api.devlog("-"*30) 
