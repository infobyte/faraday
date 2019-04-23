'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
def skip(self, n):
    for x in range(n):
        action = self.plugin._pending_actions.get(block=True)
