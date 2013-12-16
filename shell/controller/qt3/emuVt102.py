# -*- coding: ISO-8859-1 -*-
# Copyright (c) 2005-2006 LOGILAB S.A. (Paris, FRANCE).
# Copyright (c) 2005-2006 CEA Grenoble
# http://www.logilab.fr/ -- mailto:contact@logilab.fr
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the CECILL license, available at
# http://www.inria.fr/valorisation/logiciels/Licence.CeCILL-V2.pdf
#
"""Provide the EmuVt102 class, responsible for the VT102 Terminal Emulation.

Based on the konsole code from Lars Doelle.

OSC: Operating System Controls (introduced by 'ESC[')
CSI: Control Sequence Introducer (introduced by 'ESC]')

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

__revision__ = '$Id: emuVt102.py,v 1.23 2006-02-15 10:24:01 alf Exp $'

import os
import qt

import keytrans as kt
from emulation import Emulation, NOTIFYBELL, NOTIFYNORMAL
from shell.core.common import CTRL
import shell.core.screen as screen
import gui.qt3.pyqonsole.widget as widget
import shell.core.ca as ca
import model.api as api

# Qt chars shortcuts
ControlButton = qt.QEvent.ControlButton
ShiftButton = qt.QEvent.ShiftButton
AltButton = qt.QEvent.AltButton

# VT102 modes
MODE_AppScreen = screen.MODES_SCREEN+0
MODE_AppCuKeys = screen.MODES_SCREEN+1
MODE_AppKeyPad = screen.MODES_SCREEN+2
MODE_Mouse1000 = screen.MODES_SCREEN+3
MODE_Ansi      = screen.MODES_SCREEN+4

# Tokens
TY_CHR = 0
def TY_CTL(A):
    return ((ord(A) & 0xff) << 8) | 1
def TY_ESC(A):
    return ((ord(A) & 0xff) << 8) | 2
def TY_ESC_CS(A, B):
    return ((ord(B) & 0xffff) << 16) | ((ord(A) & 0xff) << 8) | 3
def TY_ESC_DE(A):
    return ((ord(A) & 0xff) << 8) | 4
def TY_CSI_PS(A, N):
    return ((N & 0xffff) << 16) | ((ord(A) & 0xff) << 8) | 5
def TY_CSI_PN(A):
    return ((ord(A) & 0xff) << 8) | 6
def TY_CSI_PR(A, N):
    return ((N & 0xffff) << 16) | ((ord(A) & 0xff) << 8) | 7
def TY_VT52(A):
    return ((ord(A) & 0xff) << 8) | 8
def TY_CSI_PG(A):
    return ((ord(A) & 0xff) << 8) | 9

# Character Classes used while decoding
CTL = 1
CHR = 2
CPN = 4
DIG = 8
SCS = 16
GRP = 32
ESC = 27


# init tokenizer table
TOK_TBL = []
def init_tokenizer():
    for i in xrange(32):
        TOK_TBL.append(CTL)
    for i in xrange(32, 256):
        TOK_TBL.append(CHR)
    for s in "@ABCDGHLMPXcdfry":
        TOK_TBL[ord(s)] |= CPN
    for s in "0123456789":
        TOK_TBL[ord(s)] |= DIG
    for s in "()+*%":
        TOK_TBL[ord(s)] |= SCS
    for s in "()+*#[]%":
        TOK_TBL[ord(s)] |= GRP
init_tokenizer()

# decoder helpers
def lec(p, s, P, L, C):
    """
    P: the length of the token scanned so far.
    L: (often P-1) the position on which contents we base a decision.
    C: a character or a group of characters (taken from 'tbl').

    s: input buffer
    p: length of the input buffer
    """
    return p == P and s[L]  == C

def lun(p, cc):
    return p == 1 and cc >= 32
def eec(p, cc, C):
    return p >= 3 and cc == C
def epp(p, s):
    return p >= 3 and s[2] == ord('?')
def egt(p, s):
    return p >= 3 and s[2] == ord('>')
def les(p, s, P, L, C):
    return p == P and s[L] < 256 and (TOK_TBL[s[L]] & C) == C
def eps(p, s, cc, C):
    return p >= 3 and s[2] != ord('?') and s[2] != ord('>') and cc < 256 and (TOK_TBL[cc] & C) == C
def ees(p, cc, C):
    return p >= 3 and cc < 256 and (TOK_TBL[cc] & C) == C


class CharCodes:
    """VT100 Charsets

    Character Set Conversion

       The processing contains a VT100 specific code translation layer.
       It's still in use and mainly responsible for the line drawing graphics.

       These and some other glyphs are assigned to codes (0x5f-0xfe)
       normally occupied by the latin letters. Since this codes also
       appear within control sequences, the extra code conversion
       does not permute with the tokenizer and is placed behind it
       in the pipeline. It only applies to tokens, which represent
       plain characters.

       This conversion it eventually continued in Widget, since
       it might involve VT100 enhanced fonts, which have these
       particular glyphs allocated in (0x00-0x1f) in their code page.
    """
    def __init__(self):
        self.charset = [0, 0, 0, 0]
        self.cu_cs = 0                        # actual charset.
        self.graphic = False                  # Some VT100 tricks
        self.pound = False                    # Some VT100 tricks
        self.trans = [0, 0, 0, 0, 0, 0, 0]    # pre-latin conversion
        self.sa_graphic = False               # saved graphic
        self.sa_pound = False                 # saved pound
        self.sa_trans = [0, 0, 0, 0, 0, 0, 0] # saved pre-latin conversion

    def reset(self):
        self.charset = [ord(c) for c in "BBBB"]
        self.cu_cs = 0
        self.graphic = False
        self.pound = False
        self.trans_from_string("[\\]{|}~")
        self.sa_graphic = False
        self.sa_pound = False

    def trans_from_string(self, string):
        #assert len(string) == 6, string
        self.trans = [ord(c) for c in string]

    def applyCharset(self, c):
        if self.graphic and 0x5f <= c and c <= 0x7e:
            return widget.VT100_GRAPHICS[c-0x5f]
        if self.pound and c == ord('#'):
            return 0xa3 # Obsolete mode
        if ord('[') <= c and c <= ord(']'):
            return self.trans[c-ord('[')+0] & 0xff
        if ord('{') <= c and c <= ord('~'):
            return self.trans[c-ord('{')+3] & 0xff
        return c

    def setCharset(self, n, cs):
        self.charset[n & 3] = cs
        self.useCharset(self.cu_cs)

    def save(self):
        self.sa_graphic = self.graphic
        self.sa_pound = self.pound
        self.sa_trans = self.trans[:]

    def restore(self):
        self.graphic = self.sa_graphic
        self.pound = self.sa_pound
        self.trans = self.sa_trans[:]

    def useCharset(self, n):
        self.cu_cs = n & 3
        self.graphic = (self.charset[n & 3] == '0')
        self.pound = (self.charset[n & 3] == 'A') # This mode is obsolete
        self.trans_from_string("[\\]{|}~") # ancient mode, identical
        # FIXME: we might better use octal strings below to prevent filter problems
        if self.charset[n & 3] == 'K':
            self.trans_from_string("ÄÖÜäöüß") # ancient mode, german
        elif self.charset[n & 3] == 'R':
            self.trans_from_string("°ç§éùè¨") # ancient mode, french


class EmuVt102(Emulation):
    """VT102 Terminal Emulation

    This class puts together the screens, the pty and the widget to a
    complete terminal emulation. Beside combining it's componentes, it
    handles the emulations's protocol.

    It consists of the following sections:
    - Incoming Bytes Event pipeline
    - Outgoing Bytes
      - Mouse Events
      - Keyboard Events
    - Modes and Charset State
    """

    def __init__(self, gui):
        super(EmuVt102, self).__init__(gui)
        self._pbuf = []
        self._argv = [0]
        # file used while in print mode
        self._print_fd = None
        # mapping with mode as key and a boolean indicating wether it's
        # activated as value
        self._curr_mode = {}
        self._save_mode = {}
        self._charset = [CharCodes(), CharCodes()]
        self._hold_screen = False
        self.reset()
        gui.myconnect("mouseSignal", self.onMouse)

    def reset(self):
        self._resetToken()
        self._resetModes()
        self._resetCharset(0)
        self._resetCharset(1)
        self._screen[0].reset()
        self._screen[1].reset()
        self._setCodec(0)

    # Processing the incoming byte stream #####################################
    """Incoming Bytes Event pipeline

    This section deals with decoding the incoming character stream.
    Decoding means here, that the stream is first seperated into `tokens'
    which are then mapped to a `meaning' provided as operations by the
    `TEScreen' class or by the emulation class itself.

    The pipeline proceeds as follows:

    - Tokenizing the ESC codes (onRcvChar)
    - VT100 code page translation of plain characters (applyCharset)
    - Interpretation of ESC codes (tau)

    The escape codes and their meaning are described in the
    technical reference of this program.


    Tokens ------------------------------------------------------------------


       Since the tokens are the central notion if this section, we've put them
       in front. They provide the syntactical elements used to represent the
       terminals operations as byte sequences.

       They are encodes here into a single machine word, so that we can later
       switch over them easily. Depending on the token itself, additional
       argument variables are filled with parameter values.

       The tokens are defined below:

       - CHR        - Printable characters     (32..255 but DEL (=127))
       - CTL        - Control characters       (0..31 but ESC (= 27), DEL)
       - ESC        - Escape codes of the form <ESC><CHR but `[]()+*#'>
       - ESC_DE     - Escape codes of the form <ESC><any of `()+*#%'> C
       - CSI_PN     - Escape codes of the form <ESC>'['     {Pn} ';' {Pn} C
       - CSI_PS     - Escape codes of the form <ESC>'['     {Pn} ';' ...  C
       - CSI_PR     - Escape codes of the form <ESC>'[' '?' {Pn} ';' ...  C
       - VT52       - VT52 escape codes
                      - <ESC><Chr>
                      - <ESC>'Y'{Pc}{Pc}
       - XTE_HA     - Xterm hacks              <ESC>`]' {Pn} `;' {Text} <BEL>
                      note that this is handled differently

       The last two forms allow list of arguments. Since the elements of
       the lists are treated individually the same way, they are passed
       as individual tokens to the interpretation. Further, because the
       meaning of the parameters are names (althought represented as numbers),
       they are includes within the token ('N').


    Tokenizer ---------------------------------------------------------------

    The tokenizers state

       The state is represented by the buffer (pbuf, ppos),
       and accompanied by decoded arguments kept in (argv,argc).
       Note that they are kept internal in the tokenizer.


    Instead of keeping an explicit state, we deduce it from the
    token scanned so far. It is then immediately combined with
    the current character to form a scanning decision.

    This is done by the following defines.

    - P is the length of the token scanned so far.
    - L (often P-1) is the position on which contents we base a decision.
    - C is a character or a group of characters (taken from 'tbl').

    Note that they need to applied in proper order.
    """

    def Xpe(self):
        return len(self._pbuf) >= 2 and self._pbuf[1] == ord(']')
    def Xte(self, cc):
        return self.Xpe() and cc == 7
    def ces(self, cc, C):
        return cc < 256 and (TOK_TBL[cc] & C) == C and not self.Xte(cc)

    def onRcvChar(self, cc):
        """char received from the subprocess"""
        if self._print_fd:
            self.printScan(cc)
            return
        if cc == 127: # VT100: ignore.
            return
        if self.ces(cc, CTL):
            # DEC HACK ALERT! Control Characters are allowed *within* esc sequences in VT100
            # This means, they do neither a resetToken nor a pushToToken. Some of them, do
            # of course. Guess this originates from a weakly layered handling of the X-on
            # X-off protocol, which comes really below this level.
            if cc == CTRL('X') or cc == CTRL('Z') or cc == ESC: # VT100: CAN or SUB
                self._resetToken()
            if cc != ESC:
                self.tau(TY_CTL(chr(cc+ord('@'))), 0, 0)
                return
        # Advance the state
        self._pbuf.append(cc)
        s = self._pbuf
        p = len(self._pbuf)

        if self.getMode(MODE_Ansi): # Decide on proper action
            if lec(p, s, 1, 0, ESC):
                pass
            elif les(p, s, 2, 1, GRP):
                pass
            elif self.Xte(cc):
                self._XtermHack()
                self._resetToken()
            elif self.Xpe():
                pass
            elif lec(p,s, 3, 2, ord('?')):
                pass
            elif lec(p, s, 3, 2, ord('>')):
                pass
            elif lun(p, cc):
                self.tau(TY_CHR, self._applyCharset(cc), 0)
                self._resetToken()
            elif lec(p, s, 2, 0, ESC):
                self.tau(TY_ESC(chr(s[1])), 0, 0)
                self._resetToken()
            elif les(p, s, 3, 1, SCS):
                self.tau(TY_ESC_CS(chr(s[1]), chr(s[2])), 0, 0)
                self._resetToken()
            elif lec(p, s, 3, 1, ord('#')):
                self.tau(TY_ESC_DE(chr(s[2])), 0, 0)
                self._resetToken()
            elif eps(p, s, cc, CPN):
                if len(self._argv)> 1:
                    q = self._argv[-1]
                else:
                    q = None
                self.tau(TY_CSI_PN(chr(cc)), self._argv[0], q)
                self._resetToken()
            elif ees(p, cc, DIG):
                self._addDigit(cc - ord('0'))
            elif eec(p, cc, ord(';')):
                self._argv.append(0)
            else:
                for arg in self._argv:
                    if epp(p, s):
                        self.tau(TY_CSI_PR(chr(cc), arg), 0, 0)
                    elif egt(p, s):
                        self.tau(TY_CSI_PG(chr(cc)), 0, 0) # spec. elif token == for ESC]>0c or ESC]>c
                    else:
                        self.tau(TY_CSI_PS(chr(cc), arg), 0, 0)
                self._resetToken()

        else: # mode VT52
            if lec(p, s, 1, 0, ESC):
                pass
            elif les(p, s, 1, 0, CHR):
                self.tau(TY_CHR, s[0], 0)
                self._resetToken()
            elif lec(p, s, 2, 1, ord('Y')):
                pass
            elif lec(p, s, 3, 1, ord('Y')):
                pass
            elif p < 4:
                self.tau(TY_VT52(chr(s[1])), 0, 0)
                self._resetToken()
            else:
                self.tau(TY_VT52(chr(s[1])), s[2], s[3])
                self._resetToken()


    def tau(self, token, p, q):
        """
        Interpretation of ESC codes
        ---------------------------

        Now that the incoming character stream is properly tokenized,
        meaning is assigned to them. These are either operations of
        the current screen, or of the emulation class itself.

        The token to be interpreteted comes in as a machine word
        possibly accompanied by two parameters.

        Likewise, the operations assigned to, come with up to two
        arguments. One could consider to make up a proper table
        from the function below.

        The technical reference manual provides more informations
        about this mapping.
        """
        if token == TY_CHR: self._scr.showCharacter(p) # UTF16

        # 127 DEL: ignored on input

        elif token == TY_CTL('@') : pass # NUL: ignored
        elif token == TY_CTL('A') : pass # SOH: ignored
        elif token == TY_CTL('B') : pass # STX: ignored
        elif token == TY_CTL('C') : pass # ETX: ignored
        elif token == TY_CTL('D') : pass # EOT: ignored
        elif token == TY_CTL('E') : self.reportAnswerBack() # VT100
        elif token == TY_CTL('F') : pass # ACK: ignored
        elif token == TY_CTL('G'):
            if self._connected: # VT100
                self._gui.bell()
                self.myemit("notifySessionState", (NOTIFYBELL,))
        elif token == TY_CTL('H') : self._scr.backSpace() # VT100
        elif token == TY_CTL('I') : self._scr.tabulate()  # VT100
        elif token == TY_CTL('J') : self._scr.newLine()   # VT100
        elif token == TY_CTL('K') : self._scr.newLine()   # VT100
        elif token == TY_CTL('L') : self._scr.newLine()   # VT100
        elif token == TY_CTL('M') : self._scr.return_()   # VT100
        elif token == TY_CTL('N') : self._useCharset(1)   # VT100
        elif token == TY_CTL('O') : self._useCharset(0)   # VT100

        elif token == TY_CTL('P')  : pass # DLE: ignored
        elif token == TY_CTL('Q')  : pass # DC1: XON continue # VT100
        elif token == TY_CTL('R')  : pass # DC2: ignored
        elif token == TY_CTL('S')  : pass # DC3: XOFF halt # VT100
        elif token == TY_CTL('T')  : pass # DC4: ignored
        elif token == TY_CTL('U')  : pass # NAK: ignored
        elif token == TY_CTL('V')  : pass # SYN: ignored
        elif token == TY_CTL('W')  : pass # ETB: ignored
        elif token == TY_CTL('X')  : self._scr.showCharacter(0x2592) # VT100 XXX Not in spec
        elif token == TY_CTL('Y')  : pass # EM : ignored
        elif token == TY_CTL('Z')  : self._scr.showCharacter(0x2592) # VT100 XXX Not in spec
        elif token == TY_CTL('[')  : pass # ESC: cannot be seen here.
        elif token == TY_CTL('\\') : pass # FS : ignored
        elif token == TY_CTL(']')  : pass # GS : ignored
        elif token == TY_CTL('^')  : pass # RS : ignored
        elif token == TY_CTL('_')  : pass # US : ignored

        elif token == TY_ESC('D') : self._scr.index() # VT100
        elif token == TY_ESC('E') : self._scr.NextLine() # VT100
        elif token == TY_ESC('H') : self._scr.changeTabStop(True) # VT100
        elif token == TY_ESC('M') : self._scr.reverseIndex() # VT100
        elif token == TY_ESC('Z') : self.reportTerminalType()
        elif token == TY_ESC('c') : self.reset()

        elif token == TY_ESC('n') : self._useCharset(2)
        elif token == TY_ESC('o') : self._useCharset(3)
        elif token == TY_ESC('7') : self._saveCursor()
        elif token == TY_ESC('8') : self._restoreCursor()

        elif token == TY_ESC('=') : self.setMode(MODE_AppKeyPad)
        elif token == TY_ESC('>') : self.resetMode(MODE_AppKeyPad)
        elif token == TY_ESC('<') : self.setMode(MODE_Ansi) # VT52

        elif token == TY_ESC_CS('(', '0') : self._setCharset(0, '0') # VT100
        elif token == TY_ESC_CS('(', 'A') : self._setCharset(0, 'A') # VT100
        elif token == TY_ESC_CS('(', 'B') : self._setCharset(0, 'B') # VT100
        elif token == TY_ESC_CS('(', 'K') : self._setCharset(0, 'K') # VT220
        elif token == TY_ESC_CS('(', 'R') : self._setCharset(0, 'R') # VT220

        elif token == TY_ESC_CS(')', '0') : self._setCharset(1, '0') # VT100
        elif token == TY_ESC_CS(')', 'A') : self._setCharset(1, 'A') # VT100
        elif token == TY_ESC_CS(')', 'B') : self._setCharset(1, 'B') # VT100
        elif token == TY_ESC_CS(')', 'K') : self._setCharset(1, 'K') # VT220
        elif token == TY_ESC_CS(')', 'R') : self._setCharset(1, 'R') # VT220

        elif token == TY_ESC_CS('*', '0') : self._setCharset(2, '0') # VT100
        elif token == TY_ESC_CS('*', 'A') : self._setCharset(2, 'A') # VT100
        elif token == TY_ESC_CS('*', 'B') : self._setCharset(2, 'B') # VT100
        elif token == TY_ESC_CS('*', 'K') : self._setCharset(2, 'K') # VT220
        elif token == TY_ESC_CS('*', 'R') : self._setCharset(2, 'R') # VT220

        elif token == TY_ESC_CS('+', '0') : self._setCharset(3, '0') # VT100
        elif token == TY_ESC_CS('+', 'A') : self._setCharset(3, 'A') # VT100
        elif token == TY_ESC_CS('+', 'B') : self._setCharset(3, 'B') # VT100
        elif token == TY_ESC_CS('+', 'K') : self._setCharset(3, 'K') # VT220
        elif token == TY_ESC_CS('+', 'R') : self._setCharset(3, 'R') # VT220

        elif token == TY_ESC_CS('%', 'G') : self._setCodec(1) # LINUX
        elif token == TY_ESC_CS('%', '@') : self._setCodec(0) # LINUX

        elif token == TY_ESC_DE('3') : pass # IGNORED: double high, top half
        elif token == TY_ESC_DE('4') : pass # IGNORED: double high, bottom half
        elif token == TY_ESC_DE('5') : pass # IGNORED: single width, single high
        elif token == TY_ESC_DE('6') : pass # IGNORED: double width, single high
        elif token == TY_ESC_DE('8') : self._scr.helpAlign()

        elif token == TY_CSI_PS('K',   0): self._scr.clearToEndOfLine()
        elif token == TY_CSI_PS('K',   1): self._scr.clearToBeginOfLine()
        elif token == TY_CSI_PS('K',   2): self._scr.clearEntireLine()
        elif token == TY_CSI_PS('J',   0): self._scr.clearToEndOfScreen()
        elif token == TY_CSI_PS('J',   1): self._scr.clearToBeginOfScreen()
        elif token == TY_CSI_PS('J',   2): self._scr.clearEntireScreen()
        elif token == TY_CSI_PS('g',   0): self._scr.changeTabStop(False)  # VT100
        elif token == TY_CSI_PS('g',   3): self._scr.clearTabStops()       # VT100
        elif token == TY_CSI_PS('h',   4): self._scr.setMode(screen.MODE_Insert)
        elif token == TY_CSI_PS('h',  20): self.setMode(screen.MODE_NewLine)
        elif token == TY_CSI_PS('i',   0): pass # IGNORE: attached printer # VT100
        elif token == TY_CSI_PS('i',   4): pass # IGNORE: attached printer # VT100
        elif token == TY_CSI_PS('i',   5): self.setPrinterMode(True)     # VT100
        elif token == TY_CSI_PS('l',   4): self._scr.resetMode(screen.MODE_Insert)
        elif token == TY_CSI_PS('l',  20): self.resetMode(screen.MODE_NewLine)
        elif token == TY_CSI_PS('s',   0): self._saveCursor()    # XXX Not in spec
        elif token == TY_CSI_PS('u',   0): self._restoreCursor() # XXX Not in spec

        elif token == TY_CSI_PS('m',   0): self._scr.setDefaultRendition()
        elif token == TY_CSI_PS('m',   1): self._scr.setRendition(ca.RE_BOLD)      # VT100
        elif token == TY_CSI_PS('m',   4): self._scr.setRendition(ca.RE_UNDERLINE) # VT100
        elif token == TY_CSI_PS('m',   5): self._scr.setRendition(ca.RE_BLINK)     # VT100
        elif token == TY_CSI_PS('m',   7): self._scr.setRendition(ca.RE_REVERSE)
        elif token == TY_CSI_PS('m',  10): pass # IGNORED: mapping related # LINUX
        elif token == TY_CSI_PS('m',  11): pass # IGNORED: mapping related # LINUX
        elif token == TY_CSI_PS('m',  12): pass # IGNORED: mapping related # LINUX
        elif token == TY_CSI_PS('m',  22): self._scr.resetRendition(ca.RE_BOLD)
        elif token == TY_CSI_PS('m',  24): self._scr.resetRendition(ca.RE_UNDERLINE)
        elif token == TY_CSI_PS('m',  25): self._scr.resetRendition(ca.RE_BLINK)
        elif token == TY_CSI_PS('m',  27): self._scr.resetRendition(ca.RE_REVERSE)

        elif token == TY_CSI_PS('m',  30): self._scr.setForeColor(0)
        elif token == TY_CSI_PS('m',  31): self._scr.setForeColor(1)
        elif token == TY_CSI_PS('m',  32): self._scr.setForeColor(2)
        elif token == TY_CSI_PS('m',  33): self._scr.setForeColor(3)
        elif token == TY_CSI_PS('m',  34): self._scr.setForeColor(4)
        elif token == TY_CSI_PS('m',  35): self._scr.setForeColor(5)
        elif token == TY_CSI_PS('m',  36): self._scr.setForeColor(6)
        elif token == TY_CSI_PS('m',  37): self._scr.setForeColor(7)
        elif token == TY_CSI_PS('m',  39): self._scr.setForeColorToDefault()

        elif token == TY_CSI_PS('m',  40): self._scr.setBackColor(0)
        elif token == TY_CSI_PS('m',  41): self._scr.setBackColor(1)
        elif token == TY_CSI_PS('m',  42): self._scr.setBackColor(2)
        elif token == TY_CSI_PS('m',  43): self._scr.setBackColor(3)
        elif token == TY_CSI_PS('m',  44): self._scr.setBackColor(4)
        elif token == TY_CSI_PS('m',  45): self._scr.setBackColor(5)
        elif token == TY_CSI_PS('m',  46): self._scr.setBackColor(6)
        elif token == TY_CSI_PS('m',  47): self._scr.setBackColor(7)
        elif token == TY_CSI_PS('m',  49): self._scr.setBackColorToDefault()

        elif token == TY_CSI_PS('m',  90): self._scr.setForeColor( 8)
        elif token == TY_CSI_PS('m',  91): self._scr.setForeColor( 9)
        elif token == TY_CSI_PS('m',  92): self._scr.setForeColor(10)
        elif token == TY_CSI_PS('m',  93): self._scr.setForeColor(11)
        elif token == TY_CSI_PS('m',  94): self._scr.setForeColor(12)
        elif token == TY_CSI_PS('m',  95): self._scr.setForeColor(13)
        elif token == TY_CSI_PS('m',  96): self._scr.setForeColor(14)
        elif token == TY_CSI_PS('m',  97): self._scr.setForeColor(15)

        elif token == TY_CSI_PS('m', 100): self._scr.setBackColor( 8)
        elif token == TY_CSI_PS('m', 101): self._scr.setBackColor( 9)
        elif token == TY_CSI_PS('m', 102): self._scr.setBackColor(10)
        elif token == TY_CSI_PS('m', 103): self._scr.setBackColor(11)
        elif token == TY_CSI_PS('m', 104): self._scr.setBackColor(12)
        elif token == TY_CSI_PS('m', 105): self._scr.setBackColor(13)
        elif token == TY_CSI_PS('m', 106): self._scr.setBackColor(14)
        elif token == TY_CSI_PS('m', 107): self._scr.setBackColor(15)

        elif token == TY_CSI_PS('n', 5): self.reportStatus()
        elif token == TY_CSI_PS('n', 6): self.reportCursorPosition()
        elif token == TY_CSI_PS('q', 0): pass # IGNORED: LEDs off # VT100 XXX Not in spec
        elif token == TY_CSI_PS('q', 1): pass # IGNORED: LED1 on  # VT100 XXX Not in spec
        elif token == TY_CSI_PS('q', 2): pass # IGNORED: LED2 on  # VT100 XXX Not in spec
        elif token == TY_CSI_PS('q', 3): pass # IGNORED: LED3 on  # VT100 XXX Not in spec
        elif token == TY_CSI_PS('q', 4): pass # IGNORED: LED4 on  # VT100 XXX Not in spec
        elif token == TY_CSI_PS('x', 0):self.reportTerminalParams(2) # VT100
        elif token == TY_CSI_PS('x', 1):self.reportTerminalParams(3) # VT100

        elif token == TY_CSI_PN('@'): self._scr.insertChars(p)
        elif token == TY_CSI_PN('A'): self._scr.cursorUp(p)       # VT100
        elif token == TY_CSI_PN('B'): self._scr.cursorDown(p)     # VT100
        elif token == TY_CSI_PN('C'): self._scr.cursorRight(p)    # VT100
        elif token == TY_CSI_PN('D'): self._scr.cursorLeft(p)     # VT100
        elif token == TY_CSI_PN('G'): self._scr.setCursorX(p)     # LINUX
        elif token == TY_CSI_PN('H'): self._scr.setCursorYX(p, q) # VT100
        elif token == TY_CSI_PN('L'): self._scr.insertLines(p)
        elif token == TY_CSI_PN('M'): self._scr.deleteLines(p)
        elif token == TY_CSI_PN('P'): self._scr.deleteChars(p)
        elif token == TY_CSI_PN('X'): self._scr.eraseChars (p)
        elif token == TY_CSI_PN('c'): self.reportTerminalType()   # VT100
        elif token == TY_CSI_PN('d'): self._scr.setCursorY(p)     # LINUX
        elif token == TY_CSI_PN('f'): self._scr.setCursorYX(p, q) # VT100
        elif token == TY_CSI_PN('r'): self._setMargins(p, q)      # VT100 XXX Not in spec
        elif token == TY_CSI_PN('y'): pass # IGNORED: Confidence test # VT100 XXX Not in spec

        elif token == TY_CSI_PR('h',  1): self.setMode(MODE_AppCuKeys)     # VT100
        elif token == TY_CSI_PR('l',  1): self.resetMode(MODE_AppCuKeys)   # VT100
        elif token == TY_CSI_PR('s',  1): self.saveMode(MODE_AppCuKeys)    # FIXME
        elif token == TY_CSI_PR('r',  1): self.restoreMode(MODE_AppCuKeys) # FIXME

        elif token == TY_CSI_PR('l',  2): self.resetMode(MODE_Ansi) # VT100

        elif token == TY_CSI_PR('h',  3): self._setColumns(132) # VT100
        elif token == TY_CSI_PR('l',  3): self._setColumns(80)  # VT100

        elif token == TY_CSI_PR('h',  4): pass # IGNORED: soft scrolling # VT100
        elif token == TY_CSI_PR('l',  4): pass # IGNORED: soft scrolling # VT100

        elif token == TY_CSI_PR('h',  5): self._scr.setMode(screen.MODE_Screen)   # VT100
        elif token == TY_CSI_PR('l',  5): self._scr.resetMode(screen.MODE_Screen) # VT100

        elif token == TY_CSI_PR('h',  6): self._scr.setMode(screen.MODE_Origin)     # VT100
        elif token == TY_CSI_PR('l',  6): self._scr.resetMode(screen.MODE_Origin)   # VT100
        elif token == TY_CSI_PR('s',  6): self._scr.saveMode(screen.MODE_Origin)    # FIXME
        elif token == TY_CSI_PR('r',  6): self._scr.restoreMode(screen.MODE_Origin) # FIXME

        elif token == TY_CSI_PR('h',  7): self._scr.setMode(screen.MODE_Wrap)     # VT100
        elif token == TY_CSI_PR('l',  7): self._scr.resetMode(screen.MODE_Wrap)   # VT100
        elif token == TY_CSI_PR('s',  7): self._scr.saveMode(screen.MODE_Wrap)    # FIXME
        elif token == TY_CSI_PR('r',  7): self._scr.restoreMode(screen.MODE_Wrap) # FIXME

        elif token == TY_CSI_PR('h',  8): pass # IGNORED: autorepeat on  # VT100
        elif token == TY_CSI_PR('l',  8): pass # IGNORED: autorepeat off # VT100

        elif token == TY_CSI_PR('h',  9): pass # IGNORED: interlace # VT100
        elif token == TY_CSI_PR('l',  9): pass # IGNORED: interlace # VT100

        elif token == TY_CSI_PR('h', 25): self.setMode(screen.MODE_Cursor)   # VT100
        elif token == TY_CSI_PR('l', 25): self.resetMode(screen.MODE_Cursor) # VT100

        elif token == TY_CSI_PR('h', 41): pass # IGNORED: obsolete more(1) fix # XTERM
        elif token == TY_CSI_PR('l', 41): pass # IGNORED: obsolete more(1) fix # XTERM
        elif token == TY_CSI_PR('s', 41): pass # IGNORED: obsolete more(1) fix # XTERM
        elif token == TY_CSI_PR('r', 41): pass # IGNORED: obsolete more(1) fix # XTERM

        elif token == TY_CSI_PR('h', 47): self.setMode(MODE_AppScreen)     # VT100
        elif token == TY_CSI_PR('l', 47): self.resetMode(MODE_AppScreen)   # VT100
        elif token == TY_CSI_PR('s', 47): self.saveMode(MODE_AppScreen)    # XTERM
        elif token == TY_CSI_PR('r', 47): self.restoreMode(MODE_AppScreen) # XTERM

        #  XTerm defines the following modes:
        #  SET_VT200_MOUSE             1000
        #  SET_VT200_HIGHLIGHT_MOUSE   1001
        #  SET_BTN_EVENT_MOUSE         1002
        #  SET_ANY_EVENT_MOUSE         1003
        #
        #  FIXME: Modes 1000,1002 and 1003 have subtle differences which we don't
        #  support yet, we treat them all the same.

        elif token == TY_CSI_PR('h', 1000): self.setMode(MODE_Mouse1000) # XTERM
        elif token == TY_CSI_PR('l', 1000): self.resetMode(MODE_Mouse1000) # XTERM
        elif token == TY_CSI_PR('s', 1000): self.saveMode(MODE_Mouse1000) # XTERM
        elif token == TY_CSI_PR('r', 1000): self.restoreMode(MODE_Mouse1000) # XTERM

        elif token == TY_CSI_PR('h', 1001): pass # IGNORED: hilite mouse tracking # XTERM
        elif token == TY_CSI_PR('l', 1001): self.resetMode(MODE_Mouse1000)        # XTERM
        elif token == TY_CSI_PR('s', 1001): pass # IGNORED: hilite mouse tracking # XTERM
        elif token == TY_CSI_PR('r', 1001): pass # IGNORED: hilite mouse tracking # XTERM

        elif token == TY_CSI_PR('h', 1002): self.setMode(MODE_Mouse1000)     # XTERM
        elif token == TY_CSI_PR('l', 1002): self.resetMode(MODE_Mouse1000)   # XTERM
        elif token == TY_CSI_PR('s', 1002): self.saveMode(MODE_Mouse1000)    # XTERM
        elif token == TY_CSI_PR('r', 1002): self.restoreMode(MODE_Mouse1000) # XTERM

        elif token == TY_CSI_PR('h', 1003): self.setMode(MODE_Mouse1000)     # XTERM
        elif token == TY_CSI_PR('l', 1003): self.resetMode(MODE_Mouse1000)   # XTERM
        elif token == TY_CSI_PR('s', 1003): self.saveMode(MODE_Mouse1000)    # XTERM
        elif token == TY_CSI_PR('r', 1003): self.restoreMode(MODE_Mouse1000) # XTERM

        elif token == TY_CSI_PR('h', 1047): self.setMode(MODE_AppScreen) # XTERM
        elif token == TY_CSI_PR('l', 1047): # XTERM
            self._screen[1].clearEntireScreen()
            self.resetMode(MODE_AppScreen)
        elif token == TY_CSI_PR('s', 1047): self.saveMode(MODE_AppScreen)    # XTERM
        elif token == TY_CSI_PR('r', 1047): self.restoreMode(MODE_AppScreen) # XTERM

        # FIXME: Unitoken: save translations
        elif token == TY_CSI_PR('h', 1048): self._saveCursor() # XTERM
        elif token == TY_CSI_PR('l', 1048): self._restoreCursor() # XTERM
        elif token == TY_CSI_PR('s', 1048): self._saveCursor() # XTERM
        elif token == TY_CSI_PR('r', 1048): self._restoreCursor() # XTERM

        # FIXME: every once new sequences like this pop up in xterm.
        #        Here's a guess of what they could mean.
        elif token == TY_CSI_PR('h', 1049): # XTERM
            self._saveCursor()
            self._screen[1].clearEntireScreen()
            self.setMode(MODE_AppScreen)
        elif token == TY_CSI_PR('l', 1049): # XTERM
            self.resetMode(MODE_AppScreen)
            self._restoreCursor()

        # FIXME: when changing between vt52 and ansi mode evtl do some resetting.
        elif token == TY_VT52('A'): self._scr.cursorUp(1)    # VT52
        elif token == TY_VT52('B'): self._scr.cursorDown(1)  # VT52
        elif token == TY_VT52('C'): self._scr.cursorRight(1) # VT52
        elif token == TY_VT52('D'): self._scr.cursorLeft(1)  # VT52

        elif token == TY_VT52('F'): self._setAndUseCharset(0, '0') # VT52
        elif token == TY_VT52('G'): self._setAndUseCharset(0, 'B') # VT52

        elif token == TY_VT52('H'): self._scr.setCursorYX(1, 1) # VT52
        elif token == TY_VT52('I'): self._scr.reverseIndex() # VT52
        elif token == TY_VT52('J'): self._scr.clearToEndOfScreen() # VT52
        elif token == TY_VT52('K'): self._scr.clearToEndOfLine()       # VT52
        elif token == TY_VT52('Y'): self._scr.setCursorYX(p-31, q-31 ) # VT52
        elif token == TY_VT52('Z'): self.reportTerminalType()        # VT52
        elif token == TY_VT52('<'): self.setMode(MODE_Ansi)            # VT52
        elif token == TY_VT52('='): self.setMode(MODE_AppKeyPad)       # VT52
        elif token == TY_VT52('>'): self.resetMode(MODE_AppKeyPad)     # VT52

        elif token == TY_CSI_PG('c') : self.reportSecondaryAttributes() # VT100

        else:
            self.reportErrorToken(token, p, q);

    def reportErrorToken(self, token, p, q):
        api.devlog('undecodable %r, %r, %r' % (token, p, q))

    def reportCursorPosition(self):
        self.sendString("\033[%d;%dR" % (self._scr.getCursorX()+1,
                                         self._scr.getCursorY()+1))

    def setPrinterMode(self, on):
        if on:
            cmd = os.getenv("PRINT_COMMAND", "cat > /dev/null")
            self._print_fd = os.popen(cmd, "w")
        else:
            self._print_fd = None

    def printScan(self, cc):
        assert self._print_fd
        if cc == CTRL('Q') or cc == CTRL('S') or cc == 0:
            return
        self._pbuf.append(cc) # advance the state
        s = self._pbuf
        p = len(self._pbuf)
        if lec(p, s, 1, 0, ESC): return
        if lec(p, s, 2, 1, ord('[')): return
        if lec(p, s, 3, 2, ord('4')): return
        if lec(p, s, 3, 2, ord('5')): return
        if lec(p, s, 4, 3, ord('i')) and s[2] == ord('4'):
            self.setPrinterMode(False)
            self._resetToken()
            return
        self._print_fd.write(''.join([chr(c) for c in s]))
        self._resetToken()

    def _XtermHack(self):
        i = 2
        arg = ''
        while ord('0') <= self._pbuf[i] < ord('9'):
            arg += chr(self._pbuf[i])
            i += 1
        arg = int(arg)
        if self._pbuf[i] != ord(';'):
            self.reportErrorToken('xterm hack', len(self._pbuf), self._pbuf[-1])
        string = ''.join([chr(c) for c in self._pbuf[i+1:-1]])
        # arg=0 changes title and icon, arg=1 only icon, arg=2 only title
        self.myemit('changeTitle', (arg, string))

    # Obsolete stuff

    def reportTerminalType(self):
        if self.getMode(MODE_Ansi):
            self.sendString("\033[?1;2c") # I'm a VT100
        else:
            self.sendString("\033/Z")     # I'm a VT52

    def reportSecondaryAttributes(self):
        if self.getMode(MODE_Ansi):
            self.sendString("\033[>0;115;0c") # Why 115 ?
        else:
            self.sendString("\033/Z")     # I don't think VT52 knows about it...

    def reportTerminalParams(self, p):
        self.sendString("\033[%d;1;1;112;112;1;0x" % p) # Not really true

    def reportStatus(self):
        """VT100. Device status report. 0 = Ready"""
        self.sendString("\033[0n")

    def reportAnswerBack(self):
        """ANSWER_BACK "" // This is really obsolete VT100 stuff."""
        self.sendString(os.getenv("ANSWER_BACK", ''))

    # Mouse Handling ##########################################################

    def onMouse(self, cb, cx, cy):
        """Mouse clicks are possibly reported to the client application if
        it has issued interest in them.
        They are normally consumed by the widget for copy and paste, but may
        be propagated from the widget when gui->setMouseMarks is set via
        setMode(MODE_Mouse1000).

               `x',`y' are 1-based.
               `ev' (event) indicates the button pressed (0-2)
                            or a general mouse release (3).
        """
        if self._connected:
            self.sendString("\033[M%c%c%c" % (cb+040, cx+040, cy+040))

    # Keyboard Handling #######################################################

    def scrollLock(self, lock):
        self._hold_screen = lock
        if lock:
            self.sendString("\023") # XOFF (^S)
        else:
            self.sendString("\021") # XON (^Q)

    def _onScrollLock(self):
        self.scrollLock(not self._hold_screen)

    def onKeyPress(self, ev):
        """char received from the gui"""
        if not self._connected: # Someone else gets the keys
            return
        self.myemit("notifySessionState", (NOTIFYNORMAL,))
        ev_state = ev.state()
        try:
            entry = self._key_trans.findEntry(ev.key(),
                                              self.getMode(screen.MODE_NewLine),
                                              self.getMode(MODE_Ansi),
                                              self.getMode(MODE_AppCuKeys),
                                              ev_state & ControlButton == ControlButton,
                                              ev_state & ShiftButton == ShiftButton,
                                              ev_state & AltButton == AltButton)
        except kt.EntryNotFound:
            cmd = kt.CMD_none # if it ends up here the key is skipped
        else:
            cmd = entry.cmd
            if   cmd == kt.CMD_emitClipboard:   self._gui.emitSelection(False, False)
            elif cmd == kt.CMD_emitSelection:   self._gui.emitSelection(True, False)
            elif cmd == kt.CMD_scrollPageUp:    self._gui.doScroll(-self._gui.lines/2)
            elif cmd == kt.CMD_scrollPageDown:  self._gui.doScroll(+self._gui.lines/2)
            elif cmd == kt.CMD_scrollLineUp:    self._gui.doScroll(-1)
            elif cmd == kt.CMD_scrollLineDown:  self._gui.doScroll(+1)
            elif cmd == kt.CMD_prevSession:
                if qt.QApplication.reverseLayout():
                    self.myemit("nextSession")
                else:
                    self.myemit("prevSession")
            elif cmd == kt.CMD_nextSession:
                if qt.QApplication.reverseLayout():
                    self.myemit("prevSession")
                else:
                    self.myemit("nextSession")
            elif cmd == kt.CMD_newSession: self.myemit("newSession")
            elif cmd == kt.CMD_renameSession: self.myemit("renameSession")
            elif cmd == kt.CMD_activateMenu: self.myemit("activateMenu")
            elif cmd == kt.CMD_moveSessionLeft:
                if qt.QApplication.reverseLayout():
                    self.myemit("moveSessionRight")
                else:
                    self.myemit("moveSessionLeft")
            elif cmd == kt.CMD_moveSessionRight:
                if qt.QApplication.reverseLayout():
                    self.myemit("moveSessionLeft")
                else:
                    self.myemit("moveSessionRight")
            elif cmd == kt.CMD_scrollLock: self._onScrollLock()

        # Revert to non-history when typing
        if self._scr.hist_cursor != self._scr.getHistLines() and not ev.text().isEmpty() or \
           ev.key() == qt.QEvent.Key_Down or ev.key() == qt.QEvent.Key_Up or \
           ev.key() == qt.QEvent.Key_Left or ev.key() == qt.QEvent.Key_Right or \
           ev.key() == qt.QEvent.Key_PageUp or ev.key() == qt.QEvent.Key_PageDown:
            self._scr.hist_cursor = self._scr.getHistLines()

        if cmd == kt.CMD_send:
            #TODO: check whats up with the ALT escape... should we sendENTER too??
            if ev_state & AltButton and not entry.metaspecified():
                self.sendString("\033") # ESC this is the ALT prefix

            s_input = entry.txt
            api.devlog(">>>> CMD_send - s_input = %s" % s_input.encode("hex"))
            # if ENTER key was pressed we call this to emit a signal to process
            # user input
            if ev.key() == qt.Qt.Key_Return or ev.key() == qt.Qt.Key_Enter:
                new_input,old_input,old_len = self.sendENTER()
                # if input was changed (this could be due to a plugin that processed
                # the user input as a command and changed the options), we have to
                # verify it and send it to the tty
                if new_input is not None: # means something changed
                    self.sendString(new_input, True, old_len)
                    
            #api.devlog("Keypress:" + str(ev.key()) )
            if ev.key() == 32:
                self.sendCTRLSPACE()
            elif ev.key() == 4114: #left
                self.sendLEFT()
            elif ev.key() == 4116: #right
                self.sendRIGHT()
            elif ev.key() == 4115: #up
                self.sendUP()
            elif ev.key() == 4117: #down
                self.sendDOWN()
             
            
            self.sendString(s_input)
            return

        # fall back handling
        if not ev.text().isEmpty():
            if ev_state & AltButton:
                self.sendString("\033") # ESC this is the ALT prefix
            s = self._codec.fromUnicode(ev.text()) # Encode for application
            # FIXME: In Qt 2, QKeyEvent::text() would return "\003" for Ctrl-C etc.
            #        while in Qt 3 it returns the actual key ("c" or "C") which caused
            #        the ControlButton to be ignored. This hack seems to work for
            #        latin1 locales at least. Please anyone find a clean solution (malte)
            if ev_state & ControlButton:
                #print ev.ascii(), ev.key()
                s.fill(chr(ev.ascii()), 1)
            self.sendString(str(s))

    # Charset related part of the emulation state #############################

    def _applyCharset(self, c):
        return self._charset[self._scr is self._screen[1]].applyCharset(c)

    def _resetCharset(self, scrno):
        self._charset[scrno].reset()

    def _setCharset(self, n, cs):
        self._charset[0].setCharset(n, cs)
        self._charset[1].setCharset(n, cs)

    def _setAndUseCharset(self, n, cs):
        self._charset[self._scr is self._screen[1]].setCharset(n, cs)

    def _useCharset(self, n):
        self._charset[self._scr is self._screen[1]].useCharset(n)

    def _saveCursor(self):
        """save cursor position and rendition attribute _plugin_settings"""
        self._charset[self._scr is self._screen[1]].save()
        self._scr.saveCursor()

    def _restoreCursor(self):
        """restor cursor position and rendition attribute _plugin_settings"""
        self._charset[self._scr is self._screen[1]].restore()
        self._scr.restoreCursor()

    # Mode Operations #########################################################
    #
    # Some of the emulations state is either added to the state of the screens.
    #
    # This causes some scoping problems, since different emulations choose to
    # located the mode either to the current screen or to both.
    #
    # For strange reasons, the extend of the rendition attributes ranges over
    # all screens and not over the actual screen.
    #
    # We decided on the precise precise extend, somehow.

    def _resetModes(self):
        """Mode related part of the state. These are all booleans."""
        self.resetMode(MODE_Mouse1000)
        self.saveMode(MODE_Mouse1000)
        self.resetMode(MODE_AppScreen)
        self.saveMode(MODE_AppScreen)
        self.setMode(MODE_Ansi)
        self._hold_screen = False
        # Obsolete modes
        self.resetMode(MODE_AppCuKeys)
        self.saveMode(MODE_AppCuKeys)
        self.resetMode(screen.MODE_NewLine)
        # XXX those initialisations were missing from cpp code
        self.resetMode(MODE_AppKeyPad)
        self.resetMode(screen.MODE_Cursor)

    def setMode(self, m):
        self._curr_mode[m] = True
        if m == MODE_Mouse1000:
            self._gui.setMouseMarks(False)
        elif m == MODE_AppScreen:
            self._setScreen(1)
        if m < screen.MODES_SCREEN:
            self._screen[0].setMode(m)
            self._screen[1].setMode(m)

    def resetMode(self, m):
        self._curr_mode[m] = False
        if m == MODE_Mouse1000:
            self._gui.setMouseMarks(True)
        elif m == MODE_AppScreen:
            self._setScreen(0)
        if m < screen.MODES_SCREEN:
            self._screen[0].resetMode(m)
            self._screen[1].resetMode(m)

    def saveMode(self, m):
        self._save_mode[m] = self._curr_mode[m]

    def restoreMode(self, m):
        if self._save_mode[m]:
            self.setMode(m)
        else:
            self.resetMode(m)

    def getMode(self, m):
        return self._curr_mode[m]

    def setConnect(self, c):
        super(EmuVt102, self).setConnect(c)
        if c:
            # Refresh mouse mode
            if self.getMode(MODE_Mouse1000):
                self.setMode(MODE_Mouse1000)
            else:
                self.resetMode(MODE_Mouse1000)

    def _setMargins(self, t, b):
        self._screen[0].setMargins(t, b)
        self._screen[1].setMargins(t, b)

    # private #################################################################

    def _resetToken(self):
        self._pbuf = []
        self._argv = [0]

    def _addDigit(self, dig):
        self._argv[-1] = 10*self._argv[-1] + dig
