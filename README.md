# OLE Packager File Format
Research and documentation into the OLE Packagerformat.

The Packager format is a  legacy of OLE1 and was designed as a generic OLE embedding server for inserting objects
that don't an associated OLE server.
## OLE Packager Data Format 
```


Name            Length      Description
-------------------------------------------------------------------------------
Header	        4           Stream Header always set to 0200
Label	        Variable    Label of embedded object defaulted to filename. (Null Terminated)
OrgPath	        Variable    Original path of embedded object. (Null Terminated)
UType	        8           Unknown – Possibly a FormatId
                                – Set to 00000300 for embedded objects
                                – Set to 00000100 for linked objects
DataPathLen     8           Length of DataPath
DataPath        Variable    Extract Path and file name defaulted to %localappdata%/Temp of the source system. (Null Terminated)
DataLen	        8           Length of embedded data.
Data	        Variable    Embedded Data
OrgPathWLen     8           Length of OrgFileW
OrgPathW        Variable    Original path of embedded object. (WChar)
LabelLen        8           Length of LabelW
LabelW	        Variable    Label of embedded object defaulted to filename. (WChar)
DefPathWLen     8           Length of OrgPathW
DefPathW        Variable    Original path of embedded object. (WChar)

```

##Usage
The script can be run against Word documents (.doc), RTF files or carved OLE10Native streams.
python psparser.py sample1.doc

```
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
```  

###Extracting Data
To extract data pass the --extract switch to extract the data stream to the current directory.
The name of the file will be the MD5 hash of the embedded data
```
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
```

## Future Research
 - Investigate VBA Tail var
 - Identify what generates values in [22:26]

## References
 - https://securingtomorrow.mcafee.com/mcafee-labs/dropping-files-temp-folder-raises-security-concerns/ 
 - https://isc.sans.edu/forums/diary/Getting+the+EXE+out+of+the+RTF/6703/
 - https://www.dshield.org/forums/diary/Getting+the+EXE+out+of+the+RTF+again/8506/
 - https://social.msdn.microsoft.com/Forums/en-US/c2044da9-a7a6-40ba-ae45-4ffd07d4178b/olenativestream-structure-doesnt-match-the-documentation
