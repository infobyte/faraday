import re
import sys

def clean_dict(d):
    if not isinstance(d, dict):
        return d
    else:
        new_dict = dict()
        for key, value in d.iteritems():
            if isinstance(value, basestring):
                new_dict[key] = clean_string(value)
            elif isinstance(value, dict):
                new_dict[key] = clean_dict(value)
            elif isinstance(value, list):
                new_dict[key] = clean_list(value)
            else:
                new_dict[key] = value
        return new_dict


def clean_list(l):
    if not isinstance(l, list):
        return l
    else:
        new_list = list()
        for item in l:
            if isinstance(item, basestring):
                new_list.append(clean_string(item))
            elif isinstance(item, dict):
                new_list.append(clean_dict(item))
            elif isinstance(item, list):
                new_list.append(clean_list(item))
            else:
                new_list.append(item)
        return new_list


def clean_string(s):
    return ''.join([clean_char(x) for x in s])


def clean_char(char):
    #Get rid of the ctrl characters first.
    #http://stackoverflow.com/questions/1833873/python-regex-escape-characters
    char = re.sub('\x1b[^m]*m', '', char)
    #Clean up invalid xml
    char = remove_invalid_chars(char)
    replacements = [
        (u'\u201c', '\"'),
        (u'\u201d', '\"'),
        (u"\u001B", ' '), #http://www.fileformat.info/info/unicode/char/1b/index.htm
        (u"\u0019", ' '), #http://www.fileformat.info/info/unicode/char/19/index.htm
        (u"\u0016", ' '), #http://www.fileformat.info/info/unicode/char/16/index.htm
        (u"\u001C", ' '), #http://www.fileformat.info/info/unicode/char/1c/index.htm
        (u"\u0003", ' '), #http://www.utf8-chartable.de/unicode-utf8-table.pl?utf8=0x
        (u"\u000C", ' ')
    ]
    for rep, new_char in replacements:
        if char == rep:
            #print ord(char), char.encode('ascii', 'ignore')
            return new_char
    return char


def remove_invalid_chars(c):
    #http://stackoverflow.com/questions/1707890/fast-way-to-filter-illegal-xml-unicode-chars-in-python
    illegal_unichrs = [ (0x00, 0x08), (0x0B, 0x1F), (0x7F, 0x84), (0x86, 0x9F),
                    (0xD800, 0xDFFF), (0xFDD0, 0xFDDF), (0xFFFE, 0xFFFF),
                    (0x1FFFE, 0x1FFFF), (0x2FFFE, 0x2FFFF), (0x3FFFE, 0x3FFFF),
                    (0x4FFFE, 0x4FFFF), (0x5FFFE, 0x5FFFF), (0x6FFFE, 0x6FFFF),
                    (0x7FFFE, 0x7FFFF), (0x8FFFE, 0x8FFFF), (0x9FFFE, 0x9FFFF),
                    (0xAFFFE, 0xAFFFF), (0xBFFFE, 0xBFFFF), (0xCFFFE, 0xCFFFF),
                    (0xDFFFE, 0xDFFFF), (0xEFFFE, 0xEFFFF), (0xFFFFE, 0xFFFFF),
                    (0x10FFFE, 0x10FFFF) ]

    illegal_ranges = ["%s-%s" % (unichr(low), unichr(high))
                  for (low, high) in illegal_unichrs
                  if low < sys.maxunicode]

    illegal_xml_re = re.compile(u'[%s]' % u''.join(illegal_ranges))
    if illegal_xml_re.search(c) is not None:
        # ret = hex(ord(c))
        # ret = binascii.b2a_uu(c)
        # ret_final = ret[1:-1]
        ret = '\\x'+c.encode('hex')
        return ret
    else:
        return c
