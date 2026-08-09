from pathlib import Path

import pytest

from phishalyzer.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def load():
    def _load(name: str):
        return parse_file(FIXTURES / name)
    return _load
