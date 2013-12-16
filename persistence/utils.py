#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import sys
try:
    import xml.etree.cElementTree as ET
    
except ImportError:
    print "cElementTree could not be imported. Using ElementTree instead"
    import xml.etree.ElementTree as ET

import xml.etree.ElementTree as pyET
import model.api
    

def SafeXmlElement(tag, attrib={}, **extra):
    """
    ElementTree has some issues to persist certain types.
    This function goes through the items and makes sure types are converted
    before creating the real element.
    """
    attrib = attrib.copy()
    attrib.update(extra)
    to_update = {}
    for k,v in attrib.iteritems():
        if isinstance(v, list) or isinstance(v, tuple):
            to_update[k] = ",".join([str(i) for i in v])
        elif isinstance(v, dict):
            model.api.devlog("dict type found while creating ElementTree node %s (%s)" % (tag, str(v)))
            to_update[k] = str(v)
        elif isinstance(v, int):
            to_update[k] = str(v)
    
    for k, v in to_update.iteritems():
        attrib[k] = v
    
    return ET.Element(tag, attrib)

def custom_serialize_xml(write, elem, encoding, qnames, namespaces, indentation='\n'):
    """
    Custom function to serialize XML. Basically is a copy of ElementTree._serialize_xml
    that adds indentantion and newlines to each of the attributes in a tag.
    This results in each attribute and value in a different line that helps
    with svn synchronization to avoid file conflicts.
    This function should only be used with python 2.7
    """
    tag = elem.tag
    text = elem.text
    next_indentation = elem.tail
    if tag is ET.Comment:
        write("<!--%s-->" % pyET._encode(text, encoding))
    elif tag is ET.ProcessingInstruction:
        write("<?%s?>" % pyET._encode(text, encoding))
    else:
        tag = qnames[tag]
        if tag is None:
            if text:
                write(pyET._escape_cdata(text, encoding))
            for e in elem:
                custom_serialize_xml(write, e, encoding, qnames, None, next_indentation)
        else:
            write("<" + tag)
            items = elem.items()
            if items or namespaces:
                if namespaces:
                    for v, k in sorted(namespaces.items(),
                                       key=lambda x: x[1]):  
                        if k:
                            k = ":" + k
                        write("%s\t\txmlns%s=\"%s\"" % (
                                    indentation,
                                    k.encode(encoding),
                                    pyET._escape_attrib(v, encoding) )
                              )
                for k, v in sorted(items):
                    if isinstance(k, ET.QName):
                        k = k.text
                    if isinstance(v, ET.QName):
                        v = qnames[v.text]
                    else:
                        v = pyET._escape_attrib(v, encoding)
                    write("%s\t\t%s=\"%s\"" % (indentation, qnames[k], v))
            if text or len(elem):
                write(">")
                if text:
                    write(pyET._escape_cdata(text, encoding))
                for e in elem:
                    custom_serialize_xml(write, e, encoding, qnames, None, next_indentation)
                write("</" + tag + ">")
            else:
                write(" />")
    if elem.tail:
        write(pyET._escape_cdata(elem.tail, encoding))

def custom_xml_write(self, file, node, encoding, namespaces, indentation='\n'):
    """
    Custom write function based on ElementTree.ElementTree._write only for python 2.6
    Basically it does the same but writes each attribute in a different line
    The same was done with custom_serialize_xml for python 2.7
    """
    tag = node.tag
    next_indentation = node.tail
    if tag is pyET.Comment:
        file.write("<!-- %s -->" % pyET._escape_cdata(node.text, encoding))
    elif tag is pyET.ProcessingInstruction:
        file.write("<?%s?>" % pyET._escape_cdata(node.text, encoding))
    else:
        items = node.items()
        xmlns_items = []
        try:
            if isinstance(tag, pyET.QName) or tag[:1] == "{":
                tag, xmlns = pyET.fixtag(tag, namespaces)
                if xmlns: xmlns_items.append(xmlns)
        except TypeError:
            pyET._raise_serialization_error(tag)
        file.write("<" + pyET._encode(tag, encoding))
        if items or xmlns_items:
            items.sort()
            for k, v in items:
                try:
                    if isinstance(k, pyET.QName) or k[:1] == "{":
                        k, xmlns = pyET.fixtag(k, namespaces)
                        if xmlns: xmlns_items.append(xmlns)
                except TypeError:
                    pyET._raise_serialization_error(k)
                try:
                    if isinstance(v, pyET.QName):
                        v, xmlns = pyET.fixtag(v, namespaces)
                        if xmlns: xmlns_items.append(xmlns)
                except TypeError:
                    pyET._raise_serialization_error(v)
                file.write("%s\t\t%s=\"%s\"" % (indentation, pyET._encode(k, encoding),
                                                pyET._escape_attrib(v, encoding)))
            for k, v in xmlns_items:
                file.write("%s\t\t%s=\"%s\"" % (indentation, pyET._encode(k, encoding),
                                                pyET._escape_attrib(v, encoding)))
        if node.text or len(node):
            file.write(">")
            if node.text:
                file.write(pyET._escape_cdata(node.text, encoding))
            for n in node:
                self._write(file, n, encoding, namespaces, next_indentation)
            file.write("</" + pyET._encode(tag, encoding) + ">")
        else:
            file.write(" />")
        for k, v in xmlns_items:
            del namespaces[v]
    if node.tail:
        file.write(pyET._escape_cdata(node.tail, encoding))

major, minor = sys.version_info[0:2]
if minor == 7:
    pyET._serialize_xml = custom_serialize_xml
elif minor == 6:
    pyET.ElementTree._write = custom_xml_write
else:
    print "nothing to replace on ElementTree for python %d.%d" % (major, minor)


def indent_xml(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent_xml(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i
  
def write_xml(xml_node, filepath, parent=None):
    """
    A little helper to write xml to a file or append to parent
    """   
    if parent is None:
        indent_xml(xml_node)
        tree = ET.ElementTree(xml_node)
        tree.write(filepath, encoding="UTF-8")
    else:
        parent.append(xml_node)