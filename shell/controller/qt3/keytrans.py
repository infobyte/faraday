# Copyright (c) 2005-2006 LOGILAB S.A. (Paris, FRANCE).
# Copyright (c) 2005-2006 CEA Grenoble
# http://www.logilab.fr/ -- mailto:contact@logilab.fr
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the CECILL license, available at
# http://www.inria.fr/valorisation/logiciels/Licence.CeCILL-V2.pdf
#
"""Provide the KeyTrans class.

The keyboard translation table allows to configure pyonsoles behavior
on key strokes.
FIXME: some bug crept in, disallowing '\0' to be emitted.

Based on the konsole code from Lars Doelle.

@author: Lars Doelle
@author: Sylvain Thenault
@copyright: 2003, 2005, 2006
@organization: Logilab
@license: CECILL
"""

__revision__ = '$Id: keytrans.py,v 1.15 2006-02-15 10:24:01 alf Exp $'


import re
import sys
from os.path import basename, dirname, splitext, join, isfile
import os
import qt
#TODO: check all these paths!!
for _path in [dirname(__file__),
              join(sys.exec_prefix, 'share/pyqonsole'),
              join(dirname(__file__), "../../../../share/pyqonsole"),
              join(dirname(__file__), "../../../share/pyqonsole/ "),
              os.environ.get('PYQONSOLE_KEYTAB_DIR', './'),
              ]:
    DEFAULT_KEYTAB_FILE = join(_path, 'default.keytab')
    if isfile(DEFAULT_KEYTAB_FILE):
        break
else:
    raise ValueError("Unable to find default.keytab."
                     "Set the PYQONSOLE_KEYTAB_DIR environment variable.")
del _path

BITS_NewLine   = 0
BITS_BsHack    = 1
BITS_Ansi      = 2
BITS_AppCuKeys = 3
BITS_Control   = 4
BITS_Shift     = 5
BITS_Alt       = 6
BITS_COUNT     = 7

def encodeModes(newline, ansi, appcukeys):
    return newline + (ansi << BITS_Ansi) + (appcukeys << BITS_AppCuKeys)

def encodeButtons(control, shift, alt):
    return (control << BITS_Control) + (shift << BITS_Shift) + (alt << BITS_Alt)

CMD_none             = -1
CMD_send             =  0
CMD_emitSelection    =  1
CMD_scrollPageUp     =  2
CMD_scrollPageDown   =  3
CMD_scrollLineUp     =  4
CMD_scrollLineDown   =  5
CMD_prevSession      =  6
CMD_nextSession      =  7
CMD_newSession       =  8
CMD_activateMenu     =  9
CMD_moveSessionLeft  = 10
CMD_moveSessionRight = 11
CMD_scrollLock       = 12
CMD_emitClipboard    = 13
CMD_renameSession    = 14

_KEYMAPS = {}

def loadAll():
    kt = KeyTrans()
    kt.addKeyTrans()
    # XXX load other keytab files ?

def find(ktid=0):
    if isinstance(ktid, int):
        try:
            return _KEYMAPS[ktid]
        except KeyError:
            pass
    for kt in _KEYMAPS.values():
        if kt.id == ktid:
            return kt
    return _KEYMAPS[0]

def count():
    return len(_KEYMAPS)

class EntryNotFound(Exception): pass

class KeyEntry:
    """instances represent the individual assignments"""
    def __init__(self, ref, key, bits, mask, cmd, txt):
        self.ref = ref
        self.key = key
        self.bits = bits
        self.mask = mask
        self.cmd = cmd
        self.txt = txt

    def matches(self, key, bits, mask):
        m = self.mask & mask
        return key == self.key and (self.bits & m) == (bits & m)

    def metaspecified(self):
        return (self.mask & (1 << BITS_Alt)) and (self.bits & (1 << BITS_Alt))


class KeyTrans:
    """combines the individual assignments to a proper map
    Takes part in a collection themself.
    """

    def __init__(self, path='[builtin]'):
        self._hdr = ''
        self.num = 0
        self.path = path
        if path == '[builtin]':
            self.id = 'default'
        else:
            self.id = splitext(basename(path))[0]
        self._file_read = False
        self._table = []

    def addKeyTrans(self):
        """XXX why is this here ??"""
        self.num = count()
        _KEYMAPS[self.num] = self

    def readConfig(self):
        if self._file_read:
            return
        self._file_read = True
        if self.path == '[builtin]':
            buf = open(DEFAULT_KEYTAB_FILE)
        else:
            buf = open(self.path)
        ktr = KeytabReader(self.path, buf)
        ktr.parseTo(self)

    def addEntry(self, ref, key, bits, mask, cmd, txt):
        """returns conflicting entry if any, else create it, add it to the
        table, and return None
        """
        try:
            return self._findEntry(key, bits, mask)
        except EntryNotFound:
            entry = KeyEntry(ref, key, bits, mask, cmd, txt)
            self._table.append(entry)

    def findEntry(self, key, newline, ansi, appcukeys, control, shift, alt):
        if not self._file_read:
            self.readConfig()
        bits = encodeModes(newline, ansi, appcukeys) + encodeButtons(control, shift, alt)
        return self._findEntry(key, bits)

    def _findEntry(self, key, bits, mask=0xffff):
        for entry in self._table:
            if entry.matches(key, bits, 0xffff):
                return entry
        raise EntryNotFound('no entry matching %s %s %0x' % (key, bits, mask))

    def hdr(self):
        if not self._file_read:
            self.readConfig()
        return self._hdr



# Scanner for keyboard configuration ##########################################

OPR_SYMS = {
  "scrollLineUp":  CMD_scrollLineUp  ,
  "scrollLineDown":CMD_scrollLineDown,
  "scrollPageUp":  CMD_scrollPageUp  ,
  "scrollPageDown":CMD_scrollPageDown,
  "emitSelection": CMD_emitSelection ,
  "prevSession":   CMD_prevSession   ,
  "nextSession":   CMD_nextSession   ,
  "newSession":    CMD_newSession    ,
  "activateMenu":  CMD_activateMenu  ,
  "renameSession":  CMD_renameSession ,
  "moveSessionLeft":  CMD_moveSessionLeft   ,
  "moveSessionRight": CMD_moveSessionRight  ,
  "scrollLock":    CMD_scrollLock,
  "emitClipboard": CMD_emitClipboard,
    }

MOD_SYMS = {
  # Modifier
  "Shift":      BITS_Shift        ,
  "Control":    BITS_Control      ,
  "Alt":        BITS_Alt          ,
  # Modes
  "BsHack":     BITS_BsHack       , # deprecated
  "Ansi":       BITS_Ansi         ,
  "NewLine":    BITS_NewLine      ,
  "AppCuKeys":  BITS_AppCuKeys    ,
    }

KEY_SYMS = {
  # Grey keys
  "Escape":       qt.Qt.Key_Escape      ,
  "Tab":          qt.Qt.Key_Tab         ,
  "Backtab":      qt.Qt.Key_Backtab     ,
  "Backspace":    qt.Qt.Key_Backspace   ,
  "Return":       qt.Qt.Key_Return      ,
  "Enter":        qt.Qt.Key_Enter       ,
  "Insert":       qt.Qt.Key_Insert      ,
  "Delete":       qt.Qt.Key_Delete      ,
  "Pause":        qt.Qt.Key_Pause       ,
  "Print":        qt.Qt.Key_Print       ,
  "SysReq":       qt.Qt.Key_SysReq      ,
  "Home":         qt.Qt.Key_Home        ,
  "End":          qt.Qt.Key_End         ,
  "Left":         qt.Qt.Key_Left        ,
  "Up":           qt.Qt.Key_Up          ,
  "Right":        qt.Qt.Key_Right       ,
  "Down":         qt.Qt.Key_Down        ,
  "Prior":        qt.Qt.Key_Prior       ,
  "Next":         qt.Qt.Key_Next        ,
  "Shift":        qt.Qt.Key_Shift       ,
  "Control":      qt.Qt.Key_Control     ,
  "Meta":         qt.Qt.Key_Meta        ,
  "Alt":          qt.Qt.Key_Alt         ,
  "CapsLock":     qt.Qt.Key_CapsLock    ,
  "NumLock":      qt.Qt.Key_NumLock     ,
  "ScrollLock":   qt.Qt.Key_ScrollLock  ,
  "F1":           qt.Qt.Key_F1          ,
  "F2":           qt.Qt.Key_F2          ,
  "F3":           qt.Qt.Key_F3          ,
  "F4":           qt.Qt.Key_F4          ,
  "F5":           qt.Qt.Key_F5          ,
  "F6":           qt.Qt.Key_F6          ,
  "F7":           qt.Qt.Key_F7          ,
  "F8":           qt.Qt.Key_F8          ,
  "F9":           qt.Qt.Key_F9          ,
  "F10":          qt.Qt.Key_F10         ,
  "F11":          qt.Qt.Key_F11         ,
  "F12":          qt.Qt.Key_F12         ,
  "F13":          qt.Qt.Key_F13         ,
  "F14":          qt.Qt.Key_F14         ,
  "F15":          qt.Qt.Key_F15         ,
  "F16":          qt.Qt.Key_F16         ,
  "F17":          qt.Qt.Key_F17         ,
  "F18":          qt.Qt.Key_F18         ,
  "F19":          qt.Qt.Key_F19         ,
  "F20":          qt.Qt.Key_F20         ,
  "F21":          qt.Qt.Key_F21         ,
  "F22":          qt.Qt.Key_F22         ,
  "F23":          qt.Qt.Key_F23         ,
  "F24":          qt.Qt.Key_F24         ,
  "F25":          qt.Qt.Key_F25         ,
  "F26":          qt.Qt.Key_F26         ,
  "F27":          qt.Qt.Key_F27         ,
  "F28":          qt.Qt.Key_F28         ,
  "F29":          qt.Qt.Key_F29         ,
  "F30":          qt.Qt.Key_F30         ,
  "F31":          qt.Qt.Key_F31         ,
  "F32":          qt.Qt.Key_F32         ,
  "F33":          qt.Qt.Key_F33         ,
  "F34":          qt.Qt.Key_F34         ,
  "F35":          qt.Qt.Key_F35         ,
  "Super_L":      qt.Qt.Key_Super_L     ,
  "Super_R":      qt.Qt.Key_Super_R     ,
  "Menu":         qt.Qt.Key_Menu        ,
  "Hyper_L":      qt.Qt.Key_Hyper_L     ,
  "Hyper_R":      qt.Qt.Key_Hyper_R     ,
  # Regular keys
  "Space":        qt.Qt.Key_Space       ,
  "Exclam":       qt.Qt.Key_Exclam      ,
  "QuoteDbl":     qt.Qt.Key_QuoteDbl    ,
  "NumberSign":   qt.Qt.Key_NumberSign  ,
  "Dollar":       qt.Qt.Key_Dollar      ,
  "Percent":      qt.Qt.Key_Percent     ,
  "Ampersand":    qt.Qt.Key_Ampersand   ,
  "Apostrophe":   qt.Qt.Key_Apostrophe  ,
  "ParenLeft":    qt.Qt.Key_ParenLeft   ,
  "ParenRight":   qt.Qt.Key_ParenRight  ,
  "Asterisk":     qt.Qt.Key_Asterisk    ,
  "Plus":         qt.Qt.Key_Plus        ,
  "Comma":        qt.Qt.Key_Comma       ,
  "Minus":        qt.Qt.Key_Minus       ,
  "Period":       qt.Qt.Key_Period      ,
  "Slash":        qt.Qt.Key_Slash       ,
  "0":            qt.Qt.Key_0           ,
  "1":            qt.Qt.Key_1           ,
  "2":            qt.Qt.Key_2           ,
  "3":            qt.Qt.Key_3           ,
  "4":            qt.Qt.Key_4           ,
  "5":            qt.Qt.Key_5           ,
  "6":            qt.Qt.Key_6           ,
  "7":            qt.Qt.Key_7           ,
  "8":            qt.Qt.Key_8           ,
  "9":            qt.Qt.Key_9           ,
  "Colon":        qt.Qt.Key_Colon       ,
  "Semicolon":    qt.Qt.Key_Semicolon   ,
  "Less":         qt.Qt.Key_Less        ,
  "Equal":        qt.Qt.Key_Equal       ,
  "Greater":      qt.Qt.Key_Greater     ,
  "Question":     qt.Qt.Key_Question    ,
  "At":           qt.Qt.Key_At          ,
  "A":            qt.Qt.Key_A           ,
  "B":            qt.Qt.Key_B           ,
  "C":            qt.Qt.Key_C           ,
  "D":            qt.Qt.Key_D           ,
  "E":            qt.Qt.Key_E           ,
  "F":            qt.Qt.Key_F           ,
  "G":            qt.Qt.Key_G           ,
  "H":            qt.Qt.Key_H           ,
  "I":            qt.Qt.Key_I           ,
  "J":            qt.Qt.Key_J           ,
  "K":            qt.Qt.Key_K           ,
  "L":            qt.Qt.Key_L           ,
  "M":            qt.Qt.Key_M           ,
  "N":            qt.Qt.Key_N           ,
  "O":            qt.Qt.Key_O           ,
  "P":            qt.Qt.Key_P           ,
  "Q":            qt.Qt.Key_Q           ,
  "R":            qt.Qt.Key_R           ,
  "S":            qt.Qt.Key_S           ,
  "T":            qt.Qt.Key_T           ,
  "U":            qt.Qt.Key_U           ,
  "V":            qt.Qt.Key_V           ,
  "W":            qt.Qt.Key_W           ,
  "X":            qt.Qt.Key_X           ,
  "Y":            qt.Qt.Key_Y           ,
  "Z":            qt.Qt.Key_Z           ,
  "BracketLeft":  qt.Qt.Key_BracketLeft ,
  "Backslash":    qt.Qt.Key_Backslash   ,
  "BracketRight": qt.Qt.Key_BracketRight,
  "AsciiCircum":  qt.Qt.Key_AsciiCircum ,
  "Underscore":   qt.Qt.Key_Underscore  ,
  "QuoteLeft":    qt.Qt.Key_QuoteLeft   ,
  "BraceLeft":    qt.Qt.Key_BraceLeft   ,
  "Bar":          qt.Qt.Key_Bar         ,
  "BraceRight":   qt.Qt.Key_BraceRight  ,
  "AsciiTilde":   qt.Qt.Key_AsciiTilde  ,
    }

KEY_DEF_SPLIT_RGX = re.compile('[+-]?\W*\w+')

class KeytabReader:
    """Scanner for keyboard configuration"""

    def __init__(self, path, stream):
        self.stream = stream
        self.path = path
        self.linno = None

    def parseTo(self, kt):
        """fill the given KeyTrans according to the parsed stream

        XXX: need to check that keyboard header is encountered first
        """
        self.linno = 1
        for line in self.stream:
            line = line.strip()
            self.linno += 1
            if not line or line.startswith('#'):
                continue
            # remove comments at the end of the line
            line = line.split('#', 1)[0]
            words = line.split()
            linetype = words.pop(0)
            # check the line begins with word "key"
            if linetype == 'keyboard':
                self._parseKeyboard(kt, ' '.join(words))
            elif linetype == 'key':
                self._parseKey(kt, ' '.join(words))
            else:
                self._reportError('malformed line')

    def _parseKeyboard(self, kt, string):
        '''example keyboard line:

        keyboard "XTerm (XFree 4.x.x)"

        here only the last part is received ("keyboard" has been removed)
        '''
        if not (string[0] == '"' and string[-1] == '"'):
            self._reportError('malformed string %s' % string)
        else:
            kt._hdr = string[1:-1] # unquote

    def _parseKey(self, kt, string):
        '''example key lines

        key Escape             : "\E"
        key Tab   -Shift       : "\t"
        key Tab   +Shift-Ansi  : "\t"
        key Return-Shift+NewLine : "\r\n"
        key Return+Shift         : "\EOM"

        here only the last part is received ("key" has been removed)
        '''
        symbols, keystr = [w.strip() for w in string.split(':', 1)]
        # symbols should be a list of names with +- to concatenate them
        key = None
        mode = 0
        mask = 0
        for op_sym in KEY_DEF_SPLIT_RGX.findall(symbols):
            op_sym = op_sym.strip()
            if key is None:
                try:
                    key = KEY_SYMS[op_sym]# - 1 # XXX why -1 ?
                except KeyError:
                    self._reportError('%s is not a valid key' % op_sym)
                    return
            else:
                # search +/-
                op, mod = op_sym[0], op_sym[1:].strip()
                if not op in '+-':
                    self._reportError('expect + or - before modifier %s' % mod)
                    return
                on = op == '+'
                try:
                    bits = MOD_SYMS[mod]# - 1 # XXX why -1
                except KeyError:
                    self._reportError('%s is not a valid mode or modifier' % mod)
                    return
                if mask & (1 << bits):
                    self._reportError('mode name %s used multible times' % mod)
                else:
                    mode |= (on << bits)
                    mask |= (1 << bits)
        # decode the key
        try:
            cmd = OPR_SYMS[keystr]# - 1 # XXX why -1
        except KeyError:
            if not (keystr[0] == '"' and keystr[-1] == '"'):
                self._reportError('malformed string or operation %s' % string)
                return
            else:
                cmd = CMD_send
                keystr = eval(keystr) # unquote + evaluation of special characters
                keystr = keystr.replace('\\E', '\033')
        entry = kt.addEntry(self.linno, key, mode, mask, cmd, keystr)
        if entry:
            self._reportError('keystroke already assigned in line %d' % entry.ref)

    def _reportError(self, msg):
        print >> sys.stderr, '%s line %s: %s' % (self.linno, self.path, msg)


loadAll()
