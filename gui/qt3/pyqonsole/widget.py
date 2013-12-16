# Copyright (c) 2005-2006 LOGILAB S.A. (Paris, FRANCE).
# Copyright (c) 2005-2006 CEA Grenoble
# http://www.logilab.fr/ -- mailto:contact@logilab.fr
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the CECILL license, available at
# http://www.inria.fr/valorisation/logiciels/Licence.CeCILL-V2.pdf
#
""" Provide the Widget class.

Visible screen contents

   This class is responsible to map the `image' of a terminal emulation to the
   display. All the dependency of the emulation to a specific GUI or toolkit is
   localized here. Further, this widget has no knowledge about being part of an
   emulation, it simply work within the terminal emulation framework by exposing
   size and key events and by being ordered to show a new image.

   - The internal image has the size of the widget (evtl. rounded up)
   - The external image used in setImage can have any size.
   - (internally) the external image is simply copied to the internal
     when a setImage happens. During a resizeEvent no painting is done
     a paintEvent is expected to follow anyway.

FIXME:
   - 'image' may also be used uninitialized (it isn't in fact) in resizeEvent
   - 'font_a' not used in mouse events

TODO
   - evtl. be sensitive to `paletteChange' while using default colors.
   - set different 'rounding' styles? I.e. have a mode to show clipped chars?

Based on the konsole code from Lars Doelle.

@author: Lars Doelle
@author: Benjamin Longuet
@author: Frederic Mantegazza
@author: Cyrille Boullier
@author: Sylvain Thenault
@copyright: 2003, 2005-2006
@organization: CEA-Grenoble
@organization: Logilab
@license: CeCILL
"""

__revision__ = '$Id: widget.py,v 1.40 2006-02-15 10:24:01 alf Exp $'
#-------------------------------------------------------------------------------
import qt
import model.api as api
from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()
from shell.core import signalable
from shell.core.ca import DCA, RE_CURSOR, RE_BLINK, RE_UNDERLINE, \
                          TABLE_COLORS, DEFAULT_BACK_COLOR, ColorEntry

from model.common import TreeWordsTries
# FIXME: the rim should normally be 1, 0 only when running in full screen mode.
rimX = 0 # left/right rim width
rimY = 0 # top/bottom rim high

# width of the scrollbar
SCRWIDTH = 16

SCRNONE = 0
SCRLEFT = 1
SCRRIGHT = 2

# scroll increment used when dragging selection at top/bottom of window.
Y_MOUSE_SCROLL = 1

BELLNONE = 0
BELLSYSTEM = 1
BELLVISUAL = 2

#extern unsigned short vt100_graphics[32]

# Dnd
diNone = 0
diPending = 1
diDragging = 2


class dragInfo:
    """uninstantiable class used to handle drag and drop status"""
    state = None
    start = None
    dragObject = None

# Colors ######################################################################

#FIXME: the default color table is in session.C now.
#       We need a way to get rid of this one, here.
BASE_COLOR_TABLE = [
    # The following are almost IBM standard color codes, with some slight
    # gamma correction for the dim colors to compensate for bright X screens.
    # It contains the 8 ansiterm/xterm colors in 2 intensities.
    # Fixme: could add faint colors here, also.
    # normal
    ColorEntry(qt.QColor(0x00,0x00,0x00), 0, 0 ), ColorEntry( qt.QColor(0xB2,0xB2,0xB2), 1, 0 ), # Dfore, Dback
    ColorEntry(qt.QColor(0x00,0x00,0x00), 0, 0 ), ColorEntry( qt.QColor(0xB2,0x18,0x18), 0, 0 ), # Black, Red
    ColorEntry(qt.QColor(0x18,0xB2,0x18), 0, 0 ), ColorEntry( qt.QColor(0xB2,0x68,0x18), 0, 0 ), # Green, Yellow
    ColorEntry(qt.QColor(0x18,0x18,0xB2), 0, 0 ), ColorEntry( qt.QColor(0xB2,0x18,0xB2), 0, 0 ), # Blue,  Magenta
    ColorEntry(qt.QColor(0x18,0xB2,0xB2), 0, 0 ), ColorEntry( qt.QColor(0xB2,0xB2,0xB2), 0, 0 ), # Cyan,  White
    # intensiv
    ColorEntry(qt.QColor(0x00,0x00,0x00), 0, 1 ), ColorEntry( qt.QColor(0xFF,0xFF,0xFF), 1, 0 ),
    ColorEntry(qt.QColor(0x68,0x68,0x68), 0, 0 ), ColorEntry( qt.QColor(0xFF,0x54,0x54), 0, 0 ),
    ColorEntry(qt.QColor(0x54,0xFF,0x54), 0, 0 ), ColorEntry( qt.QColor(0xFF,0xFF,0x54), 0, 0 ),
    ColorEntry(qt.QColor(0x54,0x54,0xFF), 0, 0 ), ColorEntry( qt.QColor(0xFF,0x54,0xFF), 0, 0 ),
    ColorEntry(qt.QColor(0x54,0xFF,0xFF), 0, 0 ), ColorEntry( qt.QColor(0xFF,0xFF,0xFF), 0, 0 )
]

# Note that we use ANSI color order (bgr), while IBMPC color order is (rgb)
#
#   Code        0       1       2       3       4       5       6       7
#   ----------- ------- ------- ------- ------- ------- ------- ------- -------
#   ANSI  (bgr) Black   Red     Green   Yellow  Blue    Magenta Cyan    White
#   IBMPC (rgb) Black   Blue    Green   Cyan    Red     Magenta Yellow  White


# Font ########################################################################

#   The VT100 has 32 special graphical characters. The usual vt100 extended
#   xterm fonts have these at 0x00..0x1f.
#
#   QT's iso mapping leaves 0x00..0x7f without any changes. But the graphicals
#   come in here as proper unicode characters.
#
#   We treat non-iso10646 fonts as VT100 extended and do the requiered mapping
#   from unicode to 0x00..0x1f. The remaining translation is then left to the
#   QCodec.

# assert for i in [0..31] : vt100extended(vt100_graphics[i]) == i.

VT100_GRAPHICS = [
    # 0/8     1/9    2/10    3/11    4/12    5/13    6/14    7/15
    0x0020, 0x25C6, 0x2592, 0x2409, 0x240c, 0x240d, 0x240a, 0x00b0,
    0x00b1, 0x2424, 0x240b, 0x2518, 0x2510, 0x250c, 0x2514, 0x253c,
    0xF800, 0xF801, 0x2500, 0xF803, 0xF804, 0x251c, 0x2524, 0x2534,
    0x252c, 0x2502, 0x2264, 0x2265, 0x03C0, 0x2260, 0x00A3, 0x00b7,
]


FONTS = [
    "13",
    "7",   # tiny font, never used
    "10",  # small font
    "13",  # medium
    "15",  # large
    "20",  # huge
    "-misc-console-medium-r-normal--16-160-72-72-c-160-iso10646-1", # "Linux"
    "-misc-fixed-medium-r-normal--15-140-75-75-c-90-iso10646-1",    # "Unicode"
    ]

TOPFONT = 0

def shellSetFontAux(te, fontno):
    f = qt.QFont()
    if FONTS[fontno][0] == '-':
        f.setRawName(FONTS[fontno])
        if not f.exactMatch():
            return
    else:
        f.setFamily("fixed")
        f.setFixedPitch(True)
        f.setPixelSize(int(FONTS[fontno]))
    te.setVTFont(f)


class ShellWidget(signalable.Signalable, qt.QFrame):
    """a widget representing attributed text"""

    def __init__(self, qapp, parent=None, name=''):
        super(ShellWidget, self).__init__(parent, name)
        # application object
        self._qapp = qapp
        # current session in this widget
        self.current_session = None
        # has blinking cursor enabled
        self.has_blinking_cursor = False
        # hide text in paintEvent
        self.blinking = False
        # has characters to blink
        self.has_blinker = False
        # hide cursor in paintEvent
        self.cursor_blinking = False
        # active when self.has_blinker
        self.blink_t = qt.QTimer(self)
        # active when self.has_blinking_cursor
        self.blink_cursor_t = qt.QTimer(self)
        # require Ctrl key for drag
        self.ctrldrag = False
        # do we antialias or not
        self.antialias = False
        #self.fixed_font # has fixed pitch
        # height, width, ascend
        self.font_h = self.font_w = self.font_a = 1
        # The offsets are not yet calculated.
        # Do not calculate these too often to be more smoothly when resizing
        # pyqonsole in opaque mode.
        self.bX = self.bY = 0
        # widget size
        self.lines = 1
        self.columns = 1
        self._image = None  # [lines][columns]
        self._line_wrapped = [] # QBitArray

        self.color_table = [None] * TABLE_COLORS
        self.currentWord = ""
        self.resizing = False
        self.terminal_size_hint = False
        self.terminal_size_startup = True
        self.mouse_marks = False

        self.i_pnt_sel = None # initial selection point
        self.pnt_sel = None   # current selection point
        self._act_sel = 0      # selection state
        self._word_selection_mode = False
        self._line_selection_mode = False
        self.preserve_line_breaks = True
        self.scroll_loc = SCRNONE
        self.bell_mode = BELLSYSTEM
        # is set in mouseDoubleClickEvent and deleted
        # after QApplication::doubleClickInterval() delay
        self._possible_triple_click = False
        self._ctrl_pressed = self._shift_pressed = False

        self.m_resize_widget = None # QFrame
        self.m_resize_label = None # QLabel
        self.m_resize_timer = None # QTimer
        self.line_spacing = 0

        self.scrollbar = qt.QScrollBar(self)
        self.scrollbar.setCursor(self.arrowCursor)

        self.drop_text = ''
        self._cursor_rect = None #for quick changing of cursor

        cb = qt.QApplication.clipboard()
        self.connect(cb, qt.SIGNAL('selectionChanged()'), self.onClearSelection)
        self.connect(self.scrollbar, qt.SIGNAL('valueChanged(int)'),
                     self.scrollChanged)
        self.connect(self.blink_t, qt.SIGNAL('timeout()'), self.blinkEvent)
        self.connect(self.blink_cursor_t, qt.SIGNAL('timeout()'),
                     self.blinkCursorEvent)

        self.setMouseMarks(True)

        #self.setVTFont(qt.QFont("monaco"))
        self.setColorTable(BASE_COLOR_TABLE) # init color table
        #TODO: check if installing this event filter doesn't conflict other widgets
        self._qapp.installEventFilter(self) #FIXME: see below

        self._compose_length = 0
        # Init DnD ################################
        self.setAcceptDrops(True) # attempt
        dragInfo.state = diNone

        self.setFocusPolicy(self.WheelFocus)

        # We're just a big pixmap, no need to have a background
        # Speeds up redraws
        self.setBackgroundMode(self.NoBackground)


##     def __del__(self):
##         # FIXME: make proper destructor
##         self._qapp.removeEventFilter( self )

    def select_on_tree( self, word ):
        mw = self._qapp.mainWidget()
        host_tree_view = mw.getHostTreeView()
        host_tree_view.selectWord(word)
        
    def getDefaultBackColor(self):
        return self.color_table[DEFAULT_BACK_COLOR].color

    def getColorTable(self):
        return self.color_table
    def setColorTable(self, table):
        for i in xrange(TABLE_COLORS):
            self.color_table[i] = table[i]
        pm = self.paletteBackgroundPixmap()
        if not pm:
            self.setPaletteBackgroundColor(self.color_table[DEFAULT_BACK_COLOR].color)
        self.update()

    # FIXME: add backgroundPixmapChanged.

    def setScrollbarLocation(self, loc):
        if self.scroll_loc == loc:
            return # quickly
        self.bY = self.bX = 1
        self.scroll_loc = loc
        self.propagateSize()
        self.update()

    def setScroll(self, cursor, lines):
        self.disconnect(self.scrollbar, qt.SIGNAL('valueChanged(int)'),
                        self.scrollChanged)
        self.scrollbar.setRange(0, lines)
        self.scrollbar.setSteps(1, self.lines)
        self.scrollbar.setValue(cursor)
        self.connect(self.scrollbar, qt.SIGNAL('valueChanged(int)'),
                     self.scrollChanged)

    def doScroll(self, lines):
        self.scrollbar.setValue(self.scrollbar.value()+lines)

    def blinkingCursor(self):
        return self.has_blinking_cursor

    def setBlinkingCursor(self, blink):
        """Display operation"""
        self.has_blinking_cursor = blink
        if blink and not self.blink_cursor_t.isActive():
            self.blink_cursor_t.start(1000)
        if not blink and self.blink_cursor_t.isActive():
            self.blink_cursor_t.stop()
            if self.cursor_blinking:
                self.blinkCursorEvent()
            else:
                self.cursor_blinking = False

    def setLineSpacing(self, i):
        self.line_spacing = i
        self.setVTFont(self.font()) # Trigger an update.
   

    def emitSelection(self, useXselection, appendReturn):
        """Paste Clipboard by simulating keypress events"""
        qt.QApplication.clipboard().setSelectionMode(useXselection)
        text = qt.QApplication.clipboard().text()
        if appendReturn:
            text.append("\r")
        if not text.isEmpty():
            text.replace(qt.QRegExp("\n"), "\r")
        ev = qt.QKeyEvent(qt.QEvent.KeyPress, 0, -1, 0, text)
        self.myemit('keyPressedSignal', (ev,)) # expose as a big fat keypress event
        self.myemit('clearSelectionSignal')
        qt.QApplication.clipboard().setSelectionMode(False)

    def setImage(self, newimg, lines, columns):
        """Display Operation - The image can only be set completely.

        The size of the new image may or may not match the size of the widget.
        """
        pm = self.paletteBackgroundPixmap()
        self.setUpdatesEnabled(False)
        paint = qt.QPainter()
        paint.begin(self)
        tL  = self.contentsRect().topLeft()
        tLx = tL.x()
        tLy = tL.y()
        self.has_blinker = False
        cf = cb = cr  = -1 # undefined
        cols = min(self.columns, max(0, columns))
        oldimg = self._image
        #print 'setimage', lins, cols, self.lines, self.columns, len(oldimg), len(newimg)
        for y in xrange(min(self.lines,  max(0, lines))):
            if self.resizing: # while resizing, we're expecting a paintEvent
                break
            x = 0
            while x < cols:
                ca = newimg[y][x]
                self.has_blinker |= ca.r & RE_BLINK
                # "is" to be more effective than "==" when possible
                if ca is oldimg[y][x] or ca == oldimg[y][x]:
                    if ca.c != '' and ca.c != ' ':
                        pass

                    x += 1
                    continue
                else:
                    pass

                c = ca.c
                if not c:
                    x += 1
                    continue
                disstrU = [c]
                cr = ca.r
                cb = ca.b
                if ca.f != cf:
                    cf = ca.f
                lln = cols - x
                xlen = 1
                for xlen in xrange(1, lln):
                    cal = newimg[y][x + xlen]
                    c = cal.c
                    if not c:
                        continue # Skip trailing part of multi-col chars.
                    ocal = oldimg[y][x + xlen]
                    if (cal.f != cf or cal.b != cb or cal.r != cr or
                        (cal is ocal or cal == ocal)):
                        break
                    disstrU.append(c)

                unistr = qt.QString(u''.join(disstrU))
                self.drawAttrStr(paint,
                                 qt.QRect(self.bX+tLx+self.font_w*x,
                                          self.bY+tLy+self.font_h*y,
                                          self.font_w*xlen,
                                          self.font_h),
                                 unistr, ca, pm != None, True)
                x += xlen
        self._image = newimg
        self.drawFrame(paint)
        paint.end()
        self.setUpdatesEnabled(True)
        if self.has_blinker and not self.blink_t.isActive():
            self.blink_t.start(1000) # 1000 ms
        elif not self.has_blinker and self.blink_t.isActive():
            self.blink_t.stop()
            self.blinking = False

        if self.resizing and self.terminal_size_hint:
            if self.terminal_size_startup:
                self.terminal_size_startup = False
                return
            widget = self.m_resize_widget
            if not self.m_resize_widget:
                self.m_resize_widget = qt.QFrame(self)
                f = self.m_resize_widget.font()
                f.setPointSize(f.pointSize()*2)
                f.setBold(True)
                widget.setFont(f)
                widget.setFrameShape(self.Raised)
                widget.setMidLineWidth(4)
                l = qt.QVBoxLayout( widget, 10)
                self.m_resize_label = qt.QLabel("Size: XXX x XXX", widget)
                l.addWidget(self.m_resize_label, 1, self.AlignCenter)
                widget.setMinimumWidth(self.m_resize_label.fontMetrics().width("Size: XXX x XXX")+20)
                widget.setMinimumHeight(self.m_resize_label.sizeHint().height()+20)
                self.m_resize_timer = qt.QTimer(self)
                self.connect(self.m_resize_timer, qt.SIGNAL('timeout()'), widget.hide)
            sizeStr = qt.QString("Size: %1 x %2").arg(columns).arg(lines)
            self.m_resize_label.setText(sizeStr)
            widget.move((self.width()-widget.width())/2,
                                      (self.height()-widget.height())/2)
            widget.show()
            self.m_resize_timer.start(1000, True)

    def setLineWrapped(self, _line_wrapped):
        self._line_wrapped = _line_wrapped

    def setCursorPos(self, curx, cury):
        """Display Operation - Set XIM Position"""
        tL  = self.contentsRect().topLeft()
        tLx = tL.x()
        tLy = tL.y()
        ypos = self.bY + tLy + self.font_h*(cury-1) + self.font_a
        xpos = self.bX + tLx + self.font_w*curx
        self.setMicroFocusHint(xpos, ypos, 0, self.font_h)

    def propagateSize(self):
        oldimg = self._image
        oldlin = self.lines
        oldcol = self.columns
        self._makeImage()
        # we copy the old image to reduce flicker
        if oldimg:
            for y in xrange(min(oldlin, self.lines)):
                for x in xrange(min(oldcol, self.columns)):
                    self._image[y][x] = oldimg[y][x]
        else:
            self._clearImage()
        # NOTE: control flows from the back through the chest right into the eye.
        #      `emu' will call back via `setImage'.
        # expose resizeEvent
        self.resizing = True
        self.myemit('changedImageSizeSignal', (self.lines, self.columns))
        self.resizing = False

    def calcSize(self, cols, lins):
        """calculate the needed size for the widget to get a cols*lins
        characters terminal
        """
        frw = self.width() - self.contentsRect().width()
        frh = self.height() - self.contentsRect().height()
        if self.scroll_loc == SCRNONE:
            scw = 0
        else:
            scw = self.scrollbar.width()
        return qt.QSize(self.font_w*cols + 2*rimX + frw + scw + 2, self.font_h*lins + 2*rimY + frh + 2)


    def sizeHint(self):
        return self.size()

    def bell(self):
        if self.bell_mode == BELLSYSTEM:
            qt.QApplication.beep()
        if self.bell_mode == BELLVISUAL:
            self._swapColorTable()
            qt.QTimer.singleShot(200, self._swapColorTable)


    def setSelection(self, t):
        # Disconnect signal while WE set the clipboard
        cb = qt.QApplication.clipboard()
        self.disconnect(cb, qt.SIGNAL('selectionChanged()'), self.onClearSelection)
        cb.setSelectionMode(True)
        cb.setText(t)
        cb.setSelectionMode(False)
        cb.setText(t)
        self.connect(cb, qt.SIGNAL('selectionChanged()'), self.onClearSelection)


    def setFont(self, font):
        # ignore font change request if not coming from konsole itself
        pass

    def setVTFont(self, font):
        if not self.antialias:
            font.setStyleStrategy(qt.QFont.NoAntialias)
        qt.QFrame.setFont(self, font)
        self.fontChange(font)

    def setMouseMarks(self, on):
        self.mouse_marks = on
        self.setCursor(on and self.ibeamCursor or self.arrowCursor)

    def setTerminalSizeHint(self, on):
        self.terminal_size_hint = on

    def pasteClipboard(self):
        self.emitSelection(False, False)

    def onClearSelection(self):
        self.myemit('clearSelectionSignal')

    def setupLayout(self):
        self.setScrollbarLocation(2)
        #self.setMinimumSize(150, 70)
        self.setMinimumSize(200, 100)
        self.setBackgroundMode(qt.Qt.PaletteBackground)
        f=qt.QFont()
        f.setRawName(CONF.getFont())
        #f.setFixedPitch(True)
        #f.setPixelSize(13)

        self.shellSetFont(f)
        self.resize(self.calcSize(80, 25))

    # protected ###############################################################

    def styleChange(self, style):
        """overridden from QWidget"""
        self.propagateSize()

    def eventFilter(self, obj, e):
        """Keyboard

        FIXME: an `eventFilter' has been installed instead of a `keyPressEvent'
               due to a bug in `QT' or the ignorance of the author to prevent
               repaint events being self.emitted to the screen whenever one leaves
               or reenters the screen to/from another application.

         Troll says one needs to change focusInEvent() and focusOutEvent(),
         which would also let you have an in-focus cursor and an out-focus
         cursor like xterm does.

        for the auto-hide cursor feature, I added empty focusInEvent() and
        focusOutEvent() so that update() isn't called.
        For auto-hide, we need to get keypress-events, but we only get them when
        we have focus.
        """
        if (e.type() == qt.QEvent.Accel or
            e.type() == qt.QEvent.AccelAvailable) and self._qapp.focusWidget() == self:
            e.ignore()
            return True
        if obj != self and obj != self.parent(): # when embedded / when standalone
            return False # not us
        if e.type() == qt.QEvent.Wheel:
            qt.QApplication.sendEvent(self.scrollbar, e)

        if e.type() == qt.QEvent.KeyPress:
            if e.key() == qt.Qt.Key_Control:
                self._ctrl_pressed = True
            elif e.key() == qt.Qt.Key_Shift:
                self._shift_pressed = True
            elif (self._shift_pressed and self._ctrl_pressed):
                mw = self._qapp.mainWidget()
                if e.key() == qt.Qt.Key_T:
                    mw.createShellTab()
                    return True
                elif e.key() == qt.Qt.Key_W:
                    mw.destroyShellTab()
                    return True
                elif e.key() == qt.Qt.Key_C:
                    return True
                elif e.key() == qt.Qt.Key_V:
                    text = qt.QApplication.clipboard().text()
                    if not text.isEmpty():
                        text.replace(qt.QRegExp("\n"), "\r")
                    ev = qt.QKeyEvent(qt.QEvent.KeyPress, 0, -1, 0, text)
                    self.myemit('keyPressedSignal', (ev,)) # expose as a big fat keypress event
                    self.myemit('clearSelectionSignal')
                    qt.QApplication.clipboard().setSelectionMode(False)
                    return True
        elif e.type() == qt.QEvent.KeyRelease:
            if e.key() == qt.Qt.Key_Control:
                self._ctrl_pressed = False
            elif e.key() == qt.Qt.Key_Shift:
                self._shift_pressed = False

        if e.type() == qt.QEvent.KeyPress and not (self._ctrl_pressed and self._shift_pressed):
            self._act_sel = 0 # Key stroke implies a screen update, so TEWidget won't
                             # know where the current selection is.
            if self.has_blinking_cursor:
                self.blink_cursor_t.start(1000)
            if self.cursor_blinking:
                self.blinkCursorEvent()
            else:
                self.cursor_blinking = False
            self.myemit('keyPressedSignal', (e,)) # expose
            # in Qt2 when key events were propagated up the tree
            # (unhandled? . parent widget) they passed the event filter only once at
            # the beginning. in qt3 self has changed, that is, the event filter is
            # called each time the event is sent (see loop in qt.QApplication.notify,
            # when internalNotify() is called for KeyPress, whereas internalNotify
            # activates also the global event filter) . That's why we stop propagation
            # here.
            return True
        if e.type() == qt.QEvent.IMStart:
            self._compose_length = 0
            e.accept()
            return False
        if e.type() == qt.QEvent.IMCompose:
            text = qt.QString()
            if self._compose_length:
                text.setLength(self._compose_length)
                for i in xrange(self._compose_length):
                    text[i] = '\010'
            self._compose_length = e.text().length()
            text += e.text()
            if not text.isEmpty():
                ke = qt.QKeyEvent(qt.QEvent.KeyPress, 0,-1, 0, text)
                self.myemit('keyPressedSignal', (ke,))
            e.accept()
            return False
        if e.type() == qt.QEvent.IMEnd:
            text = qt.QString()
            if self._compose_length:
                text.setLength(self._compose_length)
                for i in xrange(self._compose_length):
                    text[i] = '\010'
            text += e.text()
            if not text.isEmpty():
                ke = qt.QKeyEvent(qt.QEvent.KeyPress, 0,-1, 0, text)
                self.myemit('keyPressedSignal', (ke,))
            e.accept()
            return False
        if e.type() == qt.QEvent.Enter:
            cb = qt.QApplication.clipboard()
            try:
                self.disconnect(cb, qt.SIGNAL('dataChanged()'), self.onClearSelection)
            except RuntimeError:
                # slot isn't connected
                pass
        elif e.type() == qt.QEvent.Leave:
            cb = qt.QApplication.clipboard()
            self.connect(cb, qt.SIGNAL('dataChanged()'), self.onClearSelection)
        return qt.QFrame.eventFilter(self, obj, e)

    def splitQstring(self, aQstr):

        list_qstr = []
        current_len = aQstr.length()

        i = -1

        state = 0
        c = 0
        while i<=current_len:
            i += 1
            current_char = aQstr.at(i)

            if current_char.isNull():
                state = 0
            elif current_char.isPrint() and not current_char.isSpace() :
            #if (current_char.isSymbol()  or current_char.isLetterOrNumber() or current_char.isPunct()) and not current_char.isSpace() :
                #if state == 2:
                if state == 2:

                    list_qstr.append(aQstr.left(i))


                    aQstr = aQstr.right(i)
                    i = -1
                    current_len = aQstr.length()
                state = 1

            else:
                if state == 1:

                    #import pdb
                    #pdb.set_trace()
                    #list_qstr.append()#qt.QString(u' '))#aQstr.left(i))
                    aQstr = aQstr.right(i)
                    i = -1
                    current_len = aQstr.length()

                state = 2

        
        list_qstr.append(aQstr.left(aQstr.length()))


        return list_qstr


                    
    def drawAttrStr(self, paint, rect, qstr, attr, pm, clear):
        """Display Operation - attributed string draw primitive"""
        #print attr.b, attr.f
        if (attr.r & RE_CURSOR) and self.hasFocus() and (not self.has_blinking_cursor or not self.cursor_blinking):
            fColor = self.color_table[attr.b].color
            bColor = self.color_table[attr.f].color
        else:
            fColor = self.color_table[attr.f].color
            bColor = self.color_table[attr.b].color
        if attr.r & RE_CURSOR:
            self._cursor_rect = rect
        if pm and self.color_table[attr.b].transparent and (not (attr.r & RE_CURSOR) or self.cursor_blinking):
            paint.setBackgroundMode(self.TransparentMode)
            if clear:
                self.erase(rect)
        else:
            if self.blinking:
                paint.fillRect(rect, bColor)
            else:
                paint.setBackgroundMode(self.OpaqueMode)
                paint.setBackgroundColor(bColor)


        w = qstr        
        if not (self.blinking and (attr.r & RE_BLINK)):
            if (attr.r and RE_CURSOR) and self.cursor_blinking:
                self.erase(rect)
            paint.setPen(fColor)

            paint.drawText(rect.x(), rect.y()+self.font_a, w)
            if (attr.r & RE_UNDERLINE) or self.color_table[attr.f].bold:
                paint.setClipRect(rect)
                if self.color_table[attr.f].bold:
                    paint.setBackgroundMode(self.TransparentMode)
                    paint.drawText(rect.x()+1, rect.y()+self.font_a, w) # second stroke
                if attr.r & RE_UNDERLINE:
                    paint.drawLine(rect.left(), rect.y()+self.font_a+1,
                                   rect.right(), rect.y()+self.font_a+1)
                paint.setClipping(False)

        if (attr.r & RE_CURSOR) and not self.hasFocus():

            if pm and self.color_table[attr.b].transparent:

                self.erase(rect)
                paint.setBackgroundMode(self.TransparentMode)
                paint.drawText(rect.x(), rect.y()+self.font_a, w)

            paint.setClipRect(rect)
            paint.drawRect(rect.x(), rect.y(), rect.width(), rect.height()-self.line_spacing)
            paint.setClipping(False)



    def paintEvent(self, pe):
        """
        The difference of this routine vs. the `setImage' is, that the drawing
        does not include a difference analysis between the old and the new
        image. Instead, the internal image is used and the painting bound by the
        PaintEvent box.
        """
        pm = self.paletteBackgroundPixmap()
        self.setUpdatesEnabled(False)
        paint = qt.QPainter()
        paint.begin(self)
        paint.setBackgroundMode(self.TransparentMode)
        # Note that the actual widget size can be slightly larger
        # that the image (the size is truncated towards the smaller
        # number of characters in `resizeEvent'. The paint rectangle
        # can thus be larger than the image, but less then the size
        # of one character.
        rect = pe.rect().intersect(self.contentsRect())
        tL  = self.contentsRect().topLeft()
        tLx = tL.x()
        tLy = tL.y()
        lux = min(self.columns-1, max(0, (rect.left()   - tLx - self.bX) / self.font_w))
        luy = min(self.lines-1,   max(0, (rect.top()    - tLy - self.bY) / self.font_h))
        rlx = min(self.columns-1, max(0, (rect.right()  - tLx - self.bX) / self.font_w))
        rly = min(self.lines-1,   max(0, (rect.bottom() - tLy - self.bY) / self.font_h))
        image = self._image
        for y in xrange(luy, rly+1):
            c = image[y][lux].c
            x = lux
            if not c and x:
                x -= 1 # Search for start of multi-col char
            while x <= rlx:
                disstrU = []
                ca = image[y][x]
                c = ca.c
                if c:
                    disstrU.append(c)
                cf = ca.f
                cb = ca.b
                cr = ca.r
                xlen = 1
                while (x+xlen <= rlx and
                       image[y][x+xlen].f == cf and
                       image[y][x+xlen].b == cb and
                       image[y][x+xlen].r == cr):
                    c = image[y][x+xlen].c
                    if c:
                        disstrU.append(c)
                    xlen += 1
                if (x+xlen < self.columns) and (not image[y][x+xlen].c):
                    xlen += 1 # Adjust for trailing part of multi-column char
                unistr = qt.QString(u''.join(disstrU))
                self.drawAttrStr(paint,
                                 qt.QRect(self.bX+tLx+self.font_w*x, self.bY+tLy+self.font_h*y, self.font_w*xlen, self.font_h),
                                 unistr, ca, pm != None, False)
                x += xlen
        self.drawFrame(paint)
        paint.end()
        self.setUpdatesEnabled(True)

    def resizeEvent(self, ev):
        # see comment in `paintEvent' concerning the rounding.
        # FIXME: could make a routine here; check width(),height()
        assert ev.size().width() == self.width()
        assert ev.size().height() == self.height()
        self.myemit('ignoreShellWidgetResize')
        self.propagateSize()



    def fontChange(self, font):
        fm = qt.QFontMetrics(font) # QFontMetrics fm(font())
        self.font_h = fm.height() + self.line_spacing
        # waba TEWidget 1.123:
        # "Base character width on widest ASCII character. Self prevents too wide
        #  characters in the presence of double wide (e.g. Japanese) characters."
        self.font_w = 1
        for i in xrange(128):
            i = chr(i)
            if not i.isalnum():
                continue
            fw = fm.width(i)
            if self.font_w < fw:
                self.font_w = fw
        if self.font_w > 200: # don't trust unrealistic value, fallback to QFontMetrics::maxWidth()
            self.font_w = fm.maxWidth()
        if self.font_w < 1:
            self.font_w = 1
            
        self.font_a = fm.ascent()
        self.propagateSize()
        self.update()

    def frameChanged(self):
        self.propagateSize()
        self.update()


    # Mouse ###################################################################

    #    Three different operations can be performed using the mouse, and the
    #    routines in self section serve all of them:
    #
    #    1) The press/release events are exposed to the application
    #    2) Marking (press and move left button) and Pasting (press middle button)
    #    3) The right mouse button is used from the configuration menu
    #
    #    NOTE: During the marking process we attempt to keep the cursor within
    #    the bounds of the text as being displayed by setting the mouse position
    #    whenever the mouse has left the text area.
    #
    #    Two reasons to do so:
    #    1) QT does not allow the `grabMouse' to confine-to the TEWidget.
    #       Thus a `XGrapPointer' would have to be used instead.
    #    2) Even if so, self would not help too much, since the text area
    #       of the TEWidget is normally not identical with it's bounds.
    #
    #    The disadvantage of the current handling is, that the mouse can visibly
    #    leave the bounds of the widget and is then moved back. Because of the
    #    current construction, and the reasons mentioned above, we cannot do better
    #    without changing the overall construction.

    def mouseDoubleClickEvent(self, ev):
        """select the word under the pointer on mouse double click, and
        eventually wait for a third click to select the entire line
        """
        if ev.button() != self.LeftButton:
            return
        x, y = self._evXY(ev)
        # pass on double click as two clicks.
        if not self.mouse_marks and not (ev.state() & self.ShiftButton):
            # Send just _ONE_ click event, since the first click of the double click
            # was already sent by the click handler!
            self.myemit('mouseSignal', (0, x+1, y+1)) # left button
            return

        self.myemit('clearSelectionSignal')
        self.i_pnt_sel = qt.QPoint(x, y + self.scrollbar.value())
        self._word_selection_mode = True
        self._act_sel = 2 # within selection
        self.myemit('beginSelectionSignal', self._wordStart(x, y))
        self.myemit('extendSelectionSignal', self._wordEnd(x, y))
        self.myemit('endSelectionSignal', (self.preserve_line_breaks,))
        self._possible_triple_click = True


        self.myemit('onDoubleClickSignal', (self._wordStart(x, y), self._wordEnd(x, y)) )
        qt.QTimer.singleShot(qt.QApplication.doubleClickInterval(), self._tripleClickTimeout)

    def mousePressEvent(self, ev):
        if self._possible_triple_click and ev.button() == self.LeftButton:
            self.mouseTripleClickEvent(ev)
            return
        if not self.contentsRect().contains(ev.pos()):
            return
        x, y = self._evXY(ev)
        self._line_selection_mode = False
        self._word_selection_mode = False
        if ev.button() == self.LeftButton:
            topleft  = self.contentsRect().topLeft()
            # XXX: this is the only place where we add self.font_w/2, why ?
            pos = qt.QPoint((ev.x()-topleft.x()-self.bX+(self.font_w/2)) / self.font_w, y)
            self.myemit('isBusySelecting', (True,)) # Keep it steady...
            # Drag only when the Control key is hold
            selected = [False]
            # The receiver of the testIsSelected() signal will adjust
            # 'selected' accordingly.
            self.myemit('testIsSelected', (pos.x(), y, selected))
            selected = selected[0]
            if (not self.ctrldrag or ev.state() & self.ControlButton) and selected:
                # The user clicked inside selected text
                dragInfo.state = diPending
                dragInfo.start = ev.pos()
            else:
                # No reason to ever start a drag event
                dragInfo.state = diNone
                self.preserve_line_breaks = not (ev.state() & self.ControlButton)
                if self.mouse_marks or (ev.state() & self.ShiftButton):
                    self.myemit('clearSelectionSignal')
                    pos.setY(y + self.scrollbar.value())
                    self.i_pnt_sel = self.pnt_sel = pos
                    self._act_sel = 1 # left mouse button pressed but nothing selected yet.
                    self.grabMouse() # handle with care!
                else:
                    self.myemit('mouseSignal', (0, x+1, y+1)) # Left button
        elif ev.button() == self.MidButton:
            if self.mouse_marks or (not self.mouse_marks and (ev.state() & self.ShiftButton)):
                self.emitSelection(True, ev.state() & self.ControlButton)
            else:
                self.myemit('mouseSignal', (1, x+1, y+1))
        elif ev.button() == self.RightButton:
            if self.mouse_marks or (ev.state() & self.ShiftButton):
                self.myemit('configureRequest', (self, ev.state() & (self.ShiftButton|self.ControlButton), ev.x(), ev.y()))
            else:
                self.myemit('mouseSignal', (2, x+1, y+1))

    def mouseReleaseEvent(self, ev):
        x, y = self._evXY(ev)
        if ev.button() == self.LeftButton:
            self.myemit('isBusySelecting', (False,)) # Ok.. we can breath again.
            if dragInfo.state == diPending:
                # We had a drag event pending but never confirmed.  Kill selection
                self.myemit('clearSelectionSignal', ())
            else:
                if self._act_sel > 1:
                    self.myemit('endSelectionSignal', (self.preserve_line_breaks,))
                self._act_sel = 0
                #FIXME: emits a release event even if the mouse is
                #       outside the range. The procedure used in `mouseMoveEvent'
                #       applies here, too.
                if not self.mouse_marks and not (ev.state() & self.ShiftButton):
                    self.myemit('mouseSignal', (3, x+1, y + 1)) # release
                self.releaseMouse()
            dragInfo.state = diNone
        if not self.mouse_marks and ((ev.button() == self.RightButton and not (ev.state() & self.ShiftButton))
                                     or ev.button() == self.MidButton):
            self.myemit('mouseSignal', (3, x+1, y+1))
            self.releaseMouse()

    def mouseMoveEvent(self, ev):
        # for auto-hiding the cursor, we need mouseTracking
        if ev.state() == self.NoButton:
            return
        if dragInfo.state == diPending:
            # we had a mouse down, but haven't confirmed a drag yet
            # if the mouse has moved sufficiently, we will confirm
            #   int distance = KGlobalSettings::dndEventDelay();
            #   int distance = 0; # FIXME
            #   if ( ev.x() > dragInfo.start.x() + distance or ev.x() < dragInfo.start.x() - distance or
            #        ev.y() > dragInfo.start.y() + distance or ev.y() < dragInfo.start.y() - distance) {
            # we've left the drag square, we can start a real drag operation now
            #      emit isBusySelecting(False); # Ok.. we can breath again.
            #      emit clearSelectionSignal();
            #      doDrag();
            return
        elif dragInfo.state == diDragging:
            # self isn't technically needed because mouseMoveEvent is suppressed during
            # Qt drag operations, replaced by dragMoveEvent
            return
        if self._act_sel == 0:
            return
        # don't extend selection while pasting
        if ev.state() & self.MidButton:
            return
        #if ( not self.contentsRect().contains(ev.pos()) ) return;
        topleft  = self.contentsRect().topLeft()
        topleftx = topleft.x()
        toplefty = topleft.y()
        scroll = self.scrollbar.value()
        # we're in the process of moving the mouse with the left button pressed
        # the mouse cursor will kept catched within the bounds of the text in
        # self widget.
        # Adjust position within text area bounds. See FIXME above.
        pos = qt.QPoint(ev.pos())
        if pos.x() < topleftx+self.bX:
            pos.setX(topleftx+self.bX)
        if pos.x() > topleftx+self.bX+self.columns*self.font_w-1:
            pos.setX(topleftx+self.bX+self.columns*self.font_w)
        if pos.y() < toplefty+self.bY:
            pos.setY(toplefty+self.bY)
        if pos.y() > toplefty+self.bY+self.lines*self.font_h-1:
            pos.setY(toplefty+self.bY+self.lines*self.font_h-1)
        # check if we produce a mouse move event by self
        if pos != ev.pos():
            self.cursor().setPos(self.mapToGlobal(pos))
        if pos.y() == toplefty+self.bY+self.lines*self.font_h-1: # scrollforward
            self.scrollbar.setValue(self.scrollbar.value() + Y_MOUSE_SCROLL)
        if pos.y() == toplefty+self.bY: # scrollbackward
            self.scrollbar.setValue(self.scrollbar.value() - Y_MOUSE_SCROLL)
        here = [(pos.x()-topleftx-self.bX+(self.font_w/2))/self.font_w,
                (pos.y()-toplefty-self.bY)/self.font_h]
        i_pnt_sel_corr = [self.i_pnt_sel.x(), self.i_pnt_sel.y() - self.scrollbar.value()]
        pnt_sel_corr = [self.pnt_sel.x(), self.pnt_sel.y() - self.scrollbar.value()]
        swapping = False
        offset = 0
        if self._word_selection_mode:
            # Extend to word boundaries
            left_not_right = (here[1] < i_pnt_sel_corr[1] or
                              here[1] == i_pnt_sel_corr[1] and here[0] < i_pnt_sel_corr[0])
            old_left_not_right = (pnt_sel_corr[1] < i_pnt_sel_corr[1] or
                                  pnt_sel_corr[1] == i_pnt_sel_corr[1] and pnt_sel_corr[0] < i_pnt_sel_corr[0])
            swapping = left_not_right != old_left_not_right
            # Find left (left_not_right ? from here : from start)
            x, y = left_not_right and here or i_pnt_sel_corr
            if (x, y) >= (0, 0) and (x, y) < (self.columns, self.lines):
                x, y = self._wordStart(x, y)
            left = [x, y]
            # Find right (left_not_right ? from start : from here)
            x, y = left_not_right and i_pnt_sel_corr or here
            if (x, y) >= (0, 0) and (x, y) < (self.columns, self.lines):
                x, y = self._wordEnd(x, y)
            right = [x, y]
            # Pick which is start (ohere) and which is extension (here)
            if left_not_right:
                here, ohere = left, right
            else:
                here, ohere = right, left
            ohere[0] += 1
        elif self._line_selection_mode:
            # Extend to complete line
            above_not_below = here[1] < i_pnt_sel_corr[1]
            swapping = True # triple click maybe selected a wrapped line
            y = (above_not_below and here or i_pnt_sel_corr)[1]
            while y > 0 and self._line_wrapped[y-1]:
                y -= 1
            above = [0, y]
            y = (above_not_below and i_pnt_sel_corr or here)[1]
            while y < self.lines-1 and self._line_wrapped[y]:
                y += 1
            below = [self.columns-1, y]
            # Pick which is start (ohere) and which is extension (here)
            if above_not_below:
                here, ohere = above, below
            else:
                here, ohere = below, above
            ohere[0] += 1
        else:
            left_not_right = (here[1] < i_pnt_sel_corr[1] or
                              here[1] == i_pnt_sel_corr[1] and here[0] < i_pnt_sel_corr[0])
            old_left_not_right = (pnt_sel_corr[1] < i_pnt_sel_corr[1] or
                                  pnt_sel_corr[1] == i_pnt_sel_corr[1] and pnt_sel_corr[0] < i_pnt_sel_corr[0])
            swapping = left_not_right != old_left_not_right
            # Find left (left_not_right ? from here : from start)
            left = left_not_right and here or i_pnt_sel_corr
            x, y = left_not_right and i_pnt_sel_corr or here
            if (x, y) >= (0, 0) and (x, y) < (self.columns, self.lines) and x < len(self._image[0]) and y < len(self._image):
                klass = self._image[y][x].charClass()
                if klass == ' ':
                    while (x < self.columns-1 and self._image[y][x].charClass() == klass and y < self.lines-1 and not self._line_wrapped[y]):
                        x += 1
                    if x < self.columns-1:
                        x, y = left_not_right and i_pnt_sel_corr or here
                    else:
                        # will be balanced later because of offset=-1
                        x += 1
            right = [x, y]
            # Pick which is start (ohere) and which is extension (here)
            if left_not_right:
                here, ohere = left, right
                offset = 0
            else:
                here, ohere = right, left
                offset = -1
        if here == pnt_sel_corr and scroll == self.scrollbar.value():
            return # not moved
        if here == ohere:
            return # It's not left, it's not right.
        if self._act_sel < 2 or swapping:
            self.myemit('beginSelectionSignal', (ohere[0]-1-offset, ohere[1]))
        self._act_sel = 2 # within selection
        self.pnt_sel = qt.QPoint(here[0], here[1] + self.scrollbar.value())
        self.myemit('extendSelectionSignal', (here[0] + offset, here[1]))

    def mouseTripleClickEvent(self, ev):
        x, y = self._evXY(ev)
        self.i_pnt_sel = qt.QPoint(x, y)
        self.myemit('clearSelectionSignal')
        self._line_selection_mode = True
        self._word_selection_mode = False
        self._act_sel = 2 # within selection
        while self.i_pnt_sel.y()>0 and self._line_wrapped[self.i_pnt_sel.y()-1]:
            self.i_pnt_sel.setY(self.i_pnt_sel.y() - 1)
        self.myemit('beginSelectionSignal', (0, self.i_pnt_sel.y()))
        while self.i_pnt_sel.y()<self.lines-1 and self._line_wrapped[self.i_pnt_sel.y()]:
            self.i_pnt_sel.setY(self.i_pnt_sel.y() + 1)
        self.myemit('extendSelectionSignal', (self.columns-1, self.i_pnt_sel.y()))
        self.myemit('endSelectionSignal', (self.preserve_line_breaks,))
        self.i_pnt_sel.setY(self.i_pnt_sel.y() + self.scrollbar.value())


    def focusInEvent(self, ev):
        """*do* erase area, to get rid of the hollow cursor rectangle"""
        self.repaint(self._cursor_rect, True)

    def focusOutEvent(self, ev):
        """don't erase area"""
        self.repaint(self._cursor_rect, False)

    def scrollChanged(self, value):
        self.myemit('changedHistoryCursor', (value,))

    def blinkEvent(self):
        """Display operation"""
        self.blinking = not self.blinking
        self.repaint(False)

    def blinkCursorEvent(self):
        self.cursor_blinking = not self.cursor_blinking
        self.repaint(self._cursor_rect, False)

    # private #################################################################

    def _clearImage(self):
        """initialize the image, for internal use only"""
        self._image = [[DCA for _ in xrange(self.columns)]
                       for _ in xrange(self.lines)]

    def _makeImage(self):
        # calculate geometry first
        # FIXME: set rimX == rimY == 0 when running in full screen mode.
        self.scrollbar.resize(qt.QApplication.style().pixelMetric(qt.QStyle.PM_ScrollBarExtent),
                              self.contentsRect().height())
        if self.scroll_loc == SCRNONE:
            self.bX = 1
            self.columns = (self.contentsRect().width() - 2 * rimX) / self.font_w
            self.scrollbar.hide()
        elif self.scroll_loc == SCRLEFT:
            self.bX = 1+self.scrollbar.width()
            self.columns = (self.contentsRect().width() - 2 * rimX - self.scrollbar.width()) / self.font_w
            self.scrollbar.move(self.contentsRect().topLeft())
            self.scrollbar.show()
        elif self.scroll_loc ==  SCRRIGHT:
            self.bX = 1
            self.columns = (self.contentsRect().width()  - 2 * rimX - self.scrollbar.width()) / self.font_w
            self.scrollbar.move(self.contentsRect().topRight() - qt.QPoint(self.scrollbar.width()-1, 0))
            self.scrollbar.show()
        if self.columns < 1:
            self.columns = 1
        # FIXME: support 'rounding' styles
        self.lines = (self.contentsRect().height() - 2 * rimY ) / self.font_h
        # then build an empty image
        self._clearImage()

    def _swapColorTable(self):
        color = self.color_table[1]
        self.color_table[1] = self.color_table[0]
        self.color_table[0] = color
        self.update()

    def _tripleClickTimeout(self):
        """resets self._possible_triple_click"""
        self._possible_triple_click = False

    def _evXY(self, ev):
        """return (x, y) coordonnate of the image's characters pointed by a
        mouse event
        """
        topleft  = self.contentsRect().topLeft()
        x = (ev.x() - topleft.x() - self.bX) // self.font_w
        y = (ev.y() - topleft.y() - self.bY) // self.font_h
        return x, y

    def _wordStart(self, x, y):
        klass = self._image[y][x].charClass()
        while (x > 0 or (y > 0 and self._line_wrapped[y-1])) \
                  and self._image[y][x].charClass() == klass:
            if x > 0:
                x -= 1
            else:
                x = self.columns - 1
                y -= 1
        # don't add 1 if x == 0
        return x and x+1, y

    def _wordEnd(self, x, y):
        klass = self._image[y][x].charClass()
        while (x < self.columns-1 or (y < self.lines-1 and self._line_wrapped[y])) \
                  and self._image[y][x].charClass() == klass:
            if x < self.columns-1:
                x += 1
            else:
                x = 0
                y += 1
        return x-1, y

    def contextMenuEvent(self, event):
        def copy(ev):
            #XXX: FIXME!!!
            # this is copying but also pasting like when the middle button is pressed
            # this should only copy!!
            if self.mouse_marks or (not self.mouse_marks and (ev.state() & self.ShiftButton)):
                qt.QApplication.clipboard().setSelectionMode(ev.state() & self.ControlButton)
                #self.emitSelection(True, ev.state() & self.ControlButton)
            else:
                self.myemit('mouseSignal', (1, x+1, y+1))
        def paste(ev):
            #XXX: FIXME!!!
            # I didn't if this is ok
            text = qt.QApplication.clipboard().text()
            if not text.isEmpty():
                text.replace(qt.QRegExp("\n"), "\r")
            ev = qt.QKeyEvent(qt.QEvent.KeyPress, 0, -1, 0, text)
            self.myemit('keyPressedSignal', (ev,)) # expose as a big fat keypress event
            self.myemit('clearSelectionSignal')
            qt.QApplication.clipboard().setSelectionMode(False)

        #TODO: esta variable popup menu en lugar de crearse aca todo el tiempo se puede
        # poner en el init y luego hacer un metodo de setup para agregarle todas las opciones
        # y asignar a cada item la funcion que corresponda (tal como se hace en el tab manager)
        popup_menu = qt.QPopupMenu(self)
        popup_menu.insertItem("Copy", lambda ev: copy(event))
        popup_menu.insertItem("Paste", lambda ev: paste(event))
        popup_menu.insertItem("Close Tab", lambda ev: ev)
        popup_menu.exec_loop(event.globalPos())

    def shellSetFont(self, font=None):
        if font is not None:
            self.setVTFont(font)
        else:
            f = qt.QFont()
            f.setFamily("fixed")
            f.setFixedPitch(True)
            f.setPixelSize(13)
            self.setVTFont(f)

