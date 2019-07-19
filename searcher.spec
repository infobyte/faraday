# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['faraday/searcher/searcher.py', 'searcher.spec'],
             binaries=[],
             datas=[],
             hiddenimports=[],
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
          name='searcher',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=False , icon='faraday/faraday/server/www/favicon.ico')
app = BUNDLE(exe,
             name='searcher.app',
             icon='faraday/faraday/server/www/favicon.ico',
             bundle_identifier=None)
