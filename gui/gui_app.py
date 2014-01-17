#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''


class NoUi(object):
    def __init__(self):
        pass

    def run(self, args):
        while True:
            # find a way to keep this thread running, until CTRL+C is pressed
            pass

    def quit(self):
        pass

    def setSplashImage(self, ipath):
        pass


class FaradayUi(object):
    def __init__(self, gui="gtk"):
        if gui == "gtk":
            from gui.gtk.application import GuiApp
            self.gui = GuiApp()
        else:
            self.gui = NoUi()

    def setSplashImage(self, ipath):
        self.gui.setSplashImage(ipath)

    def run(self, args):
        self.gui.run(args)

    def quit(self):
        self.gui.quit()
