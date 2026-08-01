import subprocess
import sys
from pathlib import Path


def test_pyright_type_check() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "pyright", "--pythonpath", sys.executable],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout
