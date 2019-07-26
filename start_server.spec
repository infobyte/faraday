# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['faraday/start_server.py'],
             pathex=['/home/faraday/faraday'],
             binaries=[],
             datas=[('faraday', 'faraday')],
             hiddenimports=['sqlalchemy.sql.default_comparator', 'backports.functools_lru_cache', 'depot.io.local', 'passlib.handlers.bcrypt', 'passlib.handlers.pbkdf2', 'passlib.handlers.misc', 'passlib.handlers.sha2_crypt', 'passlib.handlers.digests', 'xml.sax.xmlreader', 'xml.sax.expatreader', 'sqlalchemy.ext.baked', 'faraday.client.plugins.core'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='start_server',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=False )
