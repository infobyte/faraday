# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['faraday/client/bin/fplugin.py'],
             pathex=['/Users/lcubo/workspace/faraday'],
             binaries=[],
             datas=[('faraday', 'faraday')],
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
          name='fplugin',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=False )
app = BUNDLE(exe,
             name='fplugin.app',
             icon=None,
             bundle_identifier=None)
