#!/usr/bin/env python

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
'''
File: pickled_dict.py
Author: Daniel J. Foguelman
Description: A persist-to-disk picklebased dictionary with all the normal features.
'''

import cPickle as pickle
import IPython
import os
import threading
import unittest

class PickleBackedDict(dict): 
    def __init__(self, path, filename = None):
        self.path = os.path.join(path, filename) if not filename is None else path
        self.lock = threading.Lock()
        if os.path.exists(self.path):
            with open(self.path, 'rb') as f:
                self.dict = pickle.load(f)
        else:
            self.dict = {}

    def cleanUp(self):
        with self.lock:
            with open(self.path, 'wb', 0) as writer:
                self.dict = {}
                pickle.dump(self.dict, writer)


    def __setitem__(self, key, value):
        with self.lock:
            with open(self.path, 'wb', 0) as writer:
                self.dict.__setitem__(key, value)
                pickle.dump(self.dict, writer)

    def __getitem__(self, key):
        return self.dict.__getitem__(key)

    def __repr__(self):
        return self.dict.__repr__()

    def __str__(self):
        return self.dict.__str__()

class TestPickledDict(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        """docstring for tearDown"""
        pass

    def test_time_insert_and_retrieve(self):
        from time import time
        d_file = os.tmpfile()
        d = PickleBackedDict(path = d_file.name)

                                                   
        it = time() * 1000
        for i in range(10):
            d[i] = range(50) 
        et = time() * 1000

        self.assertTrue( et - it < 2500, "Inserting a millon records takes more than a 2.5sec")

        it = time() * 1000
        a = d[3]
        et = time() * 1000
        self.assertTrue( et - it < 500, "reading is a heavy task")

if __name__ == '__main__':
    unittest.main()
