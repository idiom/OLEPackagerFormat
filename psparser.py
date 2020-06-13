
#!/usr/bin/env python
# -*- coding: utf8 -*- 

__author__ = 'Sean Wilson'
__version__ = '0.0.7'

'''
----------------------------------------
Changelog
0.0.1
 - Initial Release
0.0.2
 - Fixed bug with parsing raw RTF files.
0.0.3
 - Fixed Issue #1 Parsing raw RTF files.
 - Added better support to handle malformed RTF files
0.0.4
 - Fixed issue with malformed or nonexistent wide string properties.
0.0.5
 - Added support to process zip files (OOXML) from the command line tool.
0.0.6
 - Added a check for encrypted documents by looking for EncryptedPackage within the stream names.
 - Fixed some issues where extracting embedded objects would throw an error.
0.0.7
 - Fix for Issue 4. Script now handles malformed or non Packager streams.
----------------------------------------
Copyright (c) 2018 Sean Wilson
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
----------------------------------------

----------------------------------------
Copyright (c) 2015 Sean Wilson - PhishMe
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
----------------------------------------
USAGE
The script can be run against Word documents (.doc), RTF files or carved OLE10Native streams.
python psparser.py sample1.doc
 [*] Analyzing file....
 [*] File is an OLE file...
 [*] Processing Streams...
 [*] Found Ole10Native Stream...checking for packager data
 [*] Stream contains Packager Formatted data...
  Header:         0200
  Label:
  FormatId:       00000300
  OriginalPath:   C:\Aaa\exe\v21.exe
  Extract Path:   C:\Users\M\AppData\Local\Temp\v21.exe
  Data Size:      221696
  Data (SHA1):    c8671177cc462bdd6eb1a36935e885103283f7e1
Extracting Data
To extract data pass the --extract switch to extract the data stream to the current directory.
The name of the file will be the MD5 hash of the embedded data
python psparser sample2.doc --extract
[*] Analyzing file....
 [*] File is an OLE file...
 [*] Processing Streams...
 [*] Found Ole10Native Stream...checking for packager data
 [*] Stream contains Packager Formatted data...
  Header:         0200
  Label:          krt21.exe
  FormatId:       00000300
  OriginalPath:   C:\Aaa\exe\krt21.exe
  Extract Path:   C:\Users\ADMINI~1\AppData\Local\Temp\krt21.exe
  Data Size:      281600
  Data (SHA1):    dbf612659710fa1e463693ec2cce157be9844a01
 Extracting embedded data as 7000ed249bbb16862e5e6f5af250faba
'''

import argparse
import os
import re
import struct
import hashlib
import sys
from zipfile import ZipFile
from StringIO import StringIO

try:
    import olefile
except ImportError:
    print
    print 'Error: The module olefile is required (sudo pip install olefile)'
    print
    sys.exit(-1)


class InvalidStreamError(Exception):
    pass


class PackagerStream(object):
    """
    Simple class to encapsulate object properties.
    """

    def __init__(self, rawstream):

        # Raw Stream
        self.rawstream = rawstream

        # Always set to 0200
        self.Header = None

        # The Label used within the RTF Document.
        self.Label = None

        # Original Path of the embedded object
        self.OriginalPath = None

        # Possibly a Format/Type Id
        # 00000300 -- Embedded
        # 00000100 -- Linked
        self.FormatId = None

        # Path Size
        self.DefaultExtractPathLength = 0

        # Default extraction path, essentially %localappdata% of the authoring system
        self.DefaultExtractPath = None

        # Size of embedded data
        self.DataSize = 0

        # The Embedded Data
        self.Data = None

        # The Embedded Data
        self.DefaultExtractPathWLength = 0

        # The Embedded Data
        self.DefaultExtractPathW = None

        # The Embedded Data
        self.LabelWLength = 0

        # The Embedded Data
        self.LabelW = None

        # The Embedded Data
        self.OrgFileWLength = 0

        # The Embedded Data
        self.OrgFileW = None

        self._parse_stream()

    def _processvalue(self, value):
        try:
            return value.decode('hex')
        except AttributeError:
            return value
        except TypeError:
            return value

    def _getvarstring(self, position):

        return_string = ""
        curpos = position
        endpos = 0

        if position >= len(self.rawstream):
            raise InvalidStreamError(
                "Cursor is greater than stream length. Object is malformed or not a Packager Stream.")

        while True:
            if self.rawstream[curpos:curpos + 2] == '00':
                endpos = curpos + 2
                break
            return_string += self.rawstream[curpos:curpos + 2]
            curpos += 2
        return_string = self._processvalue(return_string)
        return return_string, endpos

    def gethash(self, htype):
        try:
            if htype == 'md5':
                m = hashlib.md5()
            elif htype == 'sha1':
                m = hashlib.sha1()
            elif htype == 'sha256':
                m = hashlib.sha256()
            m.update(self.Data)
            return m.hexdigest()
        except TypeError:
            return ""

    def _parse_stream(self):
        try:
            curpos = 0
            self.Header = self.rawstream[curpos:curpos + 4]
            curpos += 4

            self.Label, curpos = self._getvarstring(curpos)

            self.OriginalPath, curpos = self._getvarstring(curpos)

            self.FormatId = self.rawstream[curpos:curpos + 8]
            curpos += 8

            self.DefaultExtractPathLength = struct.unpack('<i', bytearray.fromhex(self.rawstream[curpos:curpos + 8]))[0]
            curpos += 8

            self.DefaultExtractPath, curpos = self._getvarstring(curpos)

            self.DataSize = struct.unpack('<i', bytearray.fromhex(self.rawstream[curpos:curpos + 8]))[0]
            curpos += 8

            self.Data = self.rawstream[curpos:curpos + (self.DataSize * 2)].decode('hex')
            curpos += (self.DataSize * 2)
        except InvalidStreamError as ise:
            print ' [!] Error parsing stream -  %s' % ise
            return

        try:
            self.DefaultExtractPathWLength = struct.unpack('<i', bytearray.fromhex(self.rawstream[curpos:curpos + 8]))[
                0]
            curpos += 8
            self.DefaultExtractPathW = self.rawstream[curpos:curpos + (self.DefaultExtractPathWLength * 4)]
            curpos += (self.DefaultExtractPathWLength * 4)
        except Exception as e:
            print '   [!] Error parsing DefaultExtractPathWLength...skipping'
            self.DefaultExtractPathWLength = 0
            self.DefaultExtractPathW = ''

        try:
            self.LabelWLength = struct.unpack('<i', bytearray.fromhex(self.rawstream[curpos:curpos + 8]))[0]
            curpos += 8
            self.LabelW = self.rawstream[curpos:curpos + (self.LabelWLength * 4)]
            curpos += (self.LabelWLength * 4)
        except Exception as e:
            print '   [!] Error parsing LabelWLength...skipping'
            self.LabelWLength = 0
            self.LabelW = ''

        try:
            self.OrgFileWLength = struct.unpack('<i', bytearray.fromhex(self.rawstream[curpos:curpos + 8]))[0]
            curpos += 8

            self.OrgFileW = self.rawstream[curpos:curpos + (self.OrgFileWLength * 4)]
            curpos += (self.OrgFileWLength * 4)
        except Exception as e:
            print '   [!] Error parsing OrgFileWLength...skipping'
            self.OrgFileWLength = 0
            self.OrgFileW = ''

    def __str__(self):
        ret = ' {:<16} {}\n'.format(" Header: ", self.Header)
        ret += ' {:<16} {}\n'.format(" Label: ", self._processvalue(self.Label))
        ret += ' {:<16} {}\n'.format(" FormatId: ", self.FormatId)
        ret += ' {:<16} {}\n'.format(" OriginalPath: ", self._processvalue(self.OriginalPath))
        ret += ' {:<16} {}\n'.format(" Extract Path: ", self._processvalue(self.DefaultExtractPath))
        ret += ' {:<16} {}\n'.format(" Data Size: ", self.DataSize)
        ret += ' {:<16} {}\n'.format(" Data (SHA1): ", self.gethash('sha1'))
        return ret


class RTFDoc(object):
    ObjectType = {
        "objemb": "OLE Embedded",
        "objlink": "OLE Link",
        "objautlink": "AutLink",
        "objsub": "Mac Subscriber",
        "objpub": "Mac Publisher",
        "objicemb": "Mac Installable Command Embedder",
        "objhtml": "HTML",
        "objocx": "OLE Control"
    }

    # https://msdn.microsoft.com/en-us/library/dd942076.aspx
    FormatID = {
        1: "LinkedObject",
        2: "EmbeddedObject"
    }

    def __init__(self, targetfile):
        if not os.path.exists(targetfile):
            raise Exception("File Does not exist")

        # Get a reference to the file
        self.data = open(targetfile, 'rb').read()

    def getstring(self, position):

        return_string = ""
        curpos = position
        endpos = 0
        while True:
            if self.data[curpos:curpos + 2] == '00':
                endpos = curpos + 2
                break
            return_string += self.data[curpos:curpos + 2]
            curpos += 2
        return return_string, endpos

    def _process_value(self, value):
        try:
            return value.decode('hex')
        except TypeError:
            return value

    def scan(self, extract, use_label=False):
        """
        Scan the file for embedded objects.
        :return:
        """

        # Remove newlines from the file
        self.data = self.data.replace("\r\n", "").replace("\r", "").replace(" ", "")
        objs = re.finditer('\\object\\\\', self.data)
        for obj in objs:
            curpos = obj.end()
            objbreak = self.data.find("{", curpos)

            if self.data.find("\\", curpos) < objbreak:
                objbreak = self.data.find("\\", curpos)

            try:
                objtype = self.ObjectType[self.data[curpos:objbreak]]
            except KeyError:
                print " [!] Error Processing Object"
                print
                continue

                # Seek to the OLEVersion
            curpos = self.data.find("01050000", obj.end())
            olever = self.data[curpos:curpos + 8]

            curpos += 8
            oleformat = self.data[curpos:curpos + 8]
            curpos += 8
            stringlen = struct.unpack('<i', bytearray.fromhex(self.data[curpos:curpos + 8]))[0] * 2

            curpos += 8

            try:
                progid = self.data[curpos:curpos + stringlen].strip('\0').decode('hex')
            except TypeError:
                progid = "Unknown [%s]" % self.data[curpos:curpos + stringlen].strip('\0')

            progid = progid.strip('\0')
            curpos += stringlen + 16
            try:
                datalen = struct.unpack('<i', bytearray.fromhex(self.data[curpos:curpos + 8]))[0]
            except:
                print " [!] Error Processing Data Length"
                datalen = "N/A"

            curpos += 8

            print " ---------------------------------------"
            print " [*] Found object at:   %d" % obj.start()
            print "     Type:              %s" % objtype
            print "     OLE Version:       %s" % olever
            try:
                print "     Format:            %s (%s)" % (
                RTFDoc.FormatID[struct.unpack('<i', bytearray.fromhex(oleformat[0:8]))[0]], oleformat)
            except KeyError:
                print "     Format:            Unknown (%s)" % oleformat

            # https://msdn.microsoft.com/en-us/library/dd942454.aspx#gt_5cb94e14-04e3-46b9-9ab7-38dc0a0f4fb5
            print "     ClassName:         %s" % progid
            print "     Total Data Length: %s" % datalen

            if progid == 'Package':
                pkgobj = PackagerStream(self.data[curpos:curpos + datalen * 2])
                print " [*] Processing Embedded Package Data"
                print pkgobj

                if extract:
                    extract_object(pkgobj, use_label)

            else:
                print ' [*] Unsupported Object Format..'

            print " ---------------------------------------"
            print


def isstream(filename):
    try:
        with open(filename, 'rb') as f:
            data = f.read()
            return data[4:6].encode('hex') == '0200'
    except:
        return False


def process_olefile(oleobject):
    try:
        embedded_objects = []
        ole = olefile.OleFileIO(oleobject)
        filelist = ole.listdir()

        #
        # Quick check if EncryptedPackage is in the stream names
        # If it is we're analyzing an encypted file which isn't supported
        #
        if str(filelist).find("EncryptedPackage", 0) > 0:
            print " [!] Document is encrypted! "
            print "     You will need to process an unencrypted copy of the document"
            return

        print ' [*] Processing Streams...'
        for fname in filelist:
            if '\x01Ole10Native' in fname:
                print ' [*] Found Ole10Native Stream...checking for packager data'
                sdata = ole.openstream(fname).read()
                if sdata[4:6].encode('hex') == '0200':
                    print ' [*] Stream contains Packager Formatted data...'
                    pkgobj = PackagerStream(sdata[4:].encode('hex'))
                    print
                    print pkgobj
                    embedded_objects.append(pkgobj)

        return embedded_objects

    except IOError as io:
        print ' [!] Error Processing OLE :: %s' % io


def process_file(filename, extract, use_label):
    pkg_objects = []
    if olefile.isOleFile(filename):
        print ' [*] File is an OLE file...'
        pkg_objects = process_olefile(filename)

        if extract:
            for pkg_object in pkg_objects:
                extract_object(pkg_object, use_label)

    elif isstream(filename):
        with open(filename, 'rb') as f:
            sdata = f.read()
            print ' [*] File is an extracted Packager Stream'
            print ' [*] Stream contains Packager Formatted data...'
            pkg_obj = PackagerStream(sdata[4:].encode('hex'))
            print
            print pkg_obj

            if extract:
                extract_object(pkg_obj, use_label)
    else:
        with open(filename, 'rb') as f:
            file_data = f.read()
        if file_data[0:2] == "PK":
            print ' [*] File is a zip archive..searching for embedded objects..'
            archive = StringIO(file_data)
            zf = ZipFile(archive, "r")
            for name in zf.namelist():
                if 'oleObject' in name:
                    print ' [*] Found OLE object: %s' % name
                    pkg_objects = process_olefile(zf.read(name))
                    if extract:
                        for pkg_object in pkg_objects:
                            extract_object(pkg_object, use_label)

        else:
            # Treat the file as an rtf doc
            rd = RTFDoc(filename)
            print ' [*] Scanning file for embedded objects'
            rd.scan(extract, use_label)


def extract_object(pkg_object, use_label=False):
    if pkg_object:
        try:
            if use_label and pkg_object.Label is not None:
                print ' [*] Writing object to file :: %s' % pkg_object.Label
                with open(pkg_object.Label, 'wb') as out:
                    out.write(pkg_object.Data)
            else:
                print ' [*] Writing object to file :: %s' % pkg_object.gethash('md5')
                with open(pkg_object.gethash('md5'), 'wb') as out:
                    out.write(pkg_object.Data)
        except Exception as e:
            print ' [!] An error occurred while writing the file :: %s' % e
    else:
        print " [!] Unable to write file - No objects"


def main():
    parser = argparse.ArgumentParser(
        description="Scan RTF, Office document or Ole10Native stream for embedded packager data.")
    parser.add_argument("file",
                        help="The file to process. This can be an RTF file, Office document or extracted Ole10Native Stream.")
    parser.add_argument('--extract', dest='extract', action='store_true', help="Extract objects")
    parser.add_argument('--debug', dest='debug', action='store_true', help="Print debug information")
    parser.add_argument('--use-filenames', dest='use_label', action='store_true', help="Extract file using original filename")
    args = parser.parse_args()

    print ' [*] Analyzing file....'
    process_file(args.file, args.extract, args.use_label)


if __name__ == '__main__':
    main()
