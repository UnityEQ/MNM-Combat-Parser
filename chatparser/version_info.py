# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'MNM Network'),
            StringStruct(u'FileDescription', u'ChatParser — Chat Parser'),
            StringStruct(u'FileVersion', u'1.0.0.0'),
            StringStruct(u'InternalName', u'ChatParser'),
            StringStruct(u'OriginalFilename', u'ChatParser.exe'),
            StringStruct(u'ProductName', u'ChatParser'),
            StringStruct(u'ProductVersion', u'1.0.0.0'),
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
