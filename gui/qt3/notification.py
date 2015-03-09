'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import qt


class NotificationsDialog(qt.QDialog):
    def __init__(self, parent, notifications, modal=True):
        qt.QDialog.__init__(self, parent, "Notifications", modal)
        self.layout = qt.QVBoxLayout(self, 0, 1, "layout")
        self.layout.addWidget(NotificationsList(self, notifications))

    def sizeHint(self):
        return qt.QSize(300, 500)


class NotificationsList(qt.QListView):
    def __init__(self, parent, notifications):
        qt.QListView.__init__(self, parent)
        self.addColumn("New notifications")
        self.setColumnWidthMode(0, qt.QListView.Maximum)
        for n in notifications:
            notif_item = qt.QListViewItem(self)
            notif_item.setText(0, qt.QString(n.getMessage()))
