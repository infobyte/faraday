# Copyright (c) 2005-2006 LOGILAB S.A. (Paris, FRANCE).
# Copyright (c) 2005-2006 CEA Grenoble 
# http://www.logilab.fr/ -- mailto:contact@logilab.fr
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the CECILL license, available at
# http://www.inria.fr/valorisation/logiciels/Licence.CeCILL-V2.pdf
#
"""Provides the History class.

An arbitrary long scroll.

   One can modify the scroll only by adding either cells
   or newlines, but access it randomly.

   The model is that of an arbitrary wide typewriter scroll
   in that the scroll is a serie of lines and each line is
   a serie of cells with no overwriting permitted.

   The implementation provides arbitrary length and numbers
   of cells and line/column indexed read access to the scroll
   at constant costs.

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

__revision__ = '$Id: history.py,v 1.10 2006-02-15 10:24:01 alf Exp $'
    
    
class HistoryTypeNone(object):
    """History Type which does nothing"""
    nb_lines = 0
    
    def getScroll(self, old=None):
        """return an instance of history implementation associated with
        this type
        """
        return HistoryScrollNone()
        

class HistoryTypeBuffer(HistoryTypeNone):
    """History Type using a buffer"""
    def __init__(self, nb_lines):
        super(HistoryTypeBuffer, self).__init__()
        self.nb_lines = nb_lines
        
    def getScroll(self, old=None):
        """return an instance of history implementation associated with
        this type
        """
        if not old:
            return HistoryScrollBuffer(self.nb_lines)
        if isinstance(old, HistoryScrollBuffer):
            old.setMaxLines(self.nb_lines)
            return old
        scroll = HistoryScrollBuffer(self.nb_lines)
        start = 0
        if self.nb_lines < old.lines:
            start = old.lines - self.nb_lines
        for i in xrange(start, old.lines):
            scroll.addCells(old.getCells(i, 0), old.isWrappedLine(i))
        return scroll

    
class HistoryScrollNone(object):
    """History Scroll which does nothing"""
    
    def __init__(self, type_=HistoryTypeNone()):
        self.type = type_
        self.lines = 0
        
    def getLineLen(self, lineno):
        """return the size of the given line"""
        return 0
    
    def isWrappedLine(self, lineno):
        """tells wether the given line is a wrapped line"""
        return False
        
    def hasScroll(self):
        """return True if this history is scrollable"""
        return False
    
    def getCells(self, lineno, colno, count=None):
        """return cells of the given line"""
        return None
    
    def addCells(self, cells, wrapped=False):
        """add a line to the history with cells a list of Ca()"""
        pass
   

class HistoryScrollBuffer(HistoryScrollNone):
    """History Scroll using a circulary buffer"""
    
    def __init__(self, max_lines):
        super (HistoryScrollBuffer, self).__init__(HistoryTypeBuffer(max_lines))
        self.max_lines = max_lines
        self.lines = 0
        self.array_index = 0
        self.buff_filled = False
        self.hist_buffer = [None] * max_lines
        self.wrapped_line = [False] * max_lines
        
    def hasScroll(self):
        """return True if this history is scrollable"""
        return True
    
    def addCells(self, cells, wrapped=False):
        """add a line to the history with cells a list of Ca()"""
        self.hist_buffer[self.array_index] = cells
        self.wrapped_line[self.array_index] = wrapped
        self.array_index += 1
        if self.array_index >= self.max_lines:
            self.array_index = 0
            self.buff_filled = True
        if self.lines < self.max_lines - 1:
            self.lines += 1

    def getLineLen(self, lineno):
        """return the size of the given line"""
        if lineno >= self.max_lines:
            return 0
        line = self.hist_buffer[self._adjustLineNo(lineno)]
        if line is not None:
            return len(line)
        return 0

    def isWrappedLine(self, lineno):
        """tells wether the given line is a wrapped line"""
        if lineno >= self.max_lines:
            return 0
        return self.wrapped_line[self._adjustLineNo(lineno)]

    def getCells(self, lineno, colno, count=None):
        """return cells of the given line"""
        assert lineno < self.max_lines
        lineno = self._adjustLineNo(lineno)
        line = self.hist_buffer[lineno]
        assert line is not None
        if count is None:
            count = len(line)
        return line[colno:colno + count]

    def setMaxLines(self, max_lines):
        """change the maximum number of lines for the history"""
        self._normalize()
        if self.max_lines > max_lines:
            start = max(0, self.array_index + 2 - max_lines)
            end = start + max_lines
            self.hist_buffer = self.hist_buffer[start:end]
            self.wrapped_line = self.wrapped_line[start:end]
            if self.array_index > max_lines:
                self.array_index = max_lines - 2
        else:
            self.hist_buffer += [None] * (max_lines - self.max_lines)
            self.wrapped_line += [False] * (max_lines - self.max_lines)
        self.max_lines = max_lines
        if self.lines > max_lines - 2:
            self.lines = max_lines - 2
        self.type = HistoryTypeBuffer(max_lines)

    def _normalize(self):
        """normalize the history buffer"""
        if not self.buff_filled: # or not self.array_index:
            return
        max_lines = self.max_lines
        hist_buffer = [None] * max_lines
        wrapped_line = [False] * max_lines
        for k, i in enumerate(xrange(self.array_index - 1,
                                     self.array_index-max_lines+1, -1)):
            hist_buffer[max_lines - 3 - k] = self.hist_buffer[i]
            wrapped_line[max_lines - 3 - k] = self.wrapped_line[i]
        self.hist_buffer = hist_buffer
        self.wrapped_line = wrapped_line
        self.array_index = max_lines - 2
        self.buff_filled = False
        self.lines = max_lines - 2

    def _adjustLineNo(self, lineno):
        """adjust the given line number according to the buffer state"""
        if self.buff_filled:
            return (lineno + self.array_index + 2) % self.max_lines
        else:
            return lineno
