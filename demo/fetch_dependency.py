"""Build-only pinned simulator dependency; Phylax itself needs no pip packages."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

EXPECTED='89865929f53bd5e32b4076dde00ee86d9b8afb1686832ed74e69d55df22729c3'
with urllib.request.urlopen('https://pypi.org/pypi/pymodbus/3.11.4/json',timeout=15) as response:
    metadata=json.load(response)
wheel=next(r for r in metadata['urls'] if r['filename']=='pymodbus-3.11.4-py3-none-any.whl')
if wheel['digests']['sha256']!=EXPECTED or not wheel['url'].startswith('https://files.pythonhosted.org/'):
    raise RuntimeError('Unexpected lab dependency identity')
with urllib.request.urlopen(wheel['url'],timeout=15) as response:body=response.read(1_000_001)
if hashlib.sha256(body).hexdigest()!=EXPECTED:raise RuntimeError('Lab dependency digest mismatch')
root=Path('/opt/lab/vendor');root.mkdir()
with zipfile.ZipFile(io.BytesIO(body)) as archive:
    for name in archive.namelist():
        if name.startswith('/') or '..' in Path(name).parts:raise RuntimeError('Unsafe package member')
    archive.extractall(root)
