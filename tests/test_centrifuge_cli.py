from centrifuge_cli import __version__

import toml
from pathlib import Path


def get_version():
    path = Path(__file__).resolve().parents[1] / 'pyproject.toml'
    pyproject = toml.loads(open(str(path)).read())
    return pyproject['tool']['poetry']['version']


def test_version():
    assert __version__ == get_version()
