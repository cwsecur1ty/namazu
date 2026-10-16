# PyInstaller 6.19.0; deterministic paths rooted at this checked-in specification.
from pathlib import Path
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

root = Path(SPECPATH).parent
identity_root = Path(os.environ['NAMAZU_BUILD_IDENTITY_DIR']).resolve()
if not (identity_root / '_namazu_build_identity.py').is_file():
    raise ValueError('Run scripts/build-desktop.ps1 to generate this release identity before packaging.')
data = [(str(identity_root / 'static'), 'namazu/static'),
        (str(identity_root / 'build-identity.json'), 'namazu'),
        (str(root / 'namazu' / 'bruno_node'), 'namazu/bruno_node')]
for package in ('fastapi', 'uvicorn', 'jsonschema', 'referencing', 'schemathesis'):
    data += copy_metadata(package)
data += collect_data_files('schemathesis')
hidden = collect_submodules('namazu') + collect_submodules('schemathesis')
hidden += ['_namazu_build_identity']
hidden += ['uvicorn.logging', 'uvicorn.loops.asyncio', 'uvicorn.protocols.http.h11_impl', 'uvicorn.lifespan.on']
a = Analysis([str(root / 'desktop' / 'backend_entry.py')], pathex=[str(identity_root), str(root)],
             binaries=[], datas=data, hiddenimports=hidden,
             excludes=['tkinter', 'matplotlib', 'IPython', 'coverage'],
             noarchive=False, optimize=1)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='Namazu.Backend',
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
          console=True, disable_windowed_traceback=True)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='backend')
