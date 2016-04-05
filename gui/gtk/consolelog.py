from gi.repository import GLib, Gio, Gtk, Vte, GObject

class ConsoleLog(Gtk.Widget):
    """Defines a textView and a textBuffer to be used for displaying
    and updating logging information in the appwindow"""

    def __init__(self):
        super(Gtk.Widget, self).__init__()

        self.textBuffer = Gtk.TextBuffer()
        self.textBuffer.new()
        self.textBuffer.set_text("FARADAY \0", -1)

        self.textView = Gtk.TextView()
        self.textView.set_editable(False)
        self.textView.set_monospace(True)
        self.textView.set_justification(Gtk.Justification.LEFT)
        self.textView.set_buffer(self.textBuffer)

    def getLastPosition(self):
        # return self.textBuffer.get_end_iter()
        pass

    def getView(self):
        return self.textView

    def getBuffer(self):
        return self.textBuffer

    def customEvent(self, text, type_):
        if type_ == 3131:
            self.update(text)

    def update(self, event):
        # last_position = self.textBuffer.get_end_iter()
        # self.textBuffer.insert_at_cursor("aaa" , 3)
        print "This will be, someday, the actual text"
