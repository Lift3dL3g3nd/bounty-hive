import ast
from pathlib import Path


CLIENT_PATH = Path("bounty_hive/store/client.py")

ALLOWED_IMPORTS = {
    "typing",
    "typing_extensions",
    "abc",
}


def test_client_py_only_uses_allowed_imports():
    tree = ast.parse(CLIENT_PATH.read_text())

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                root = name.name.split(".")[0]
                assert root in ALLOWED_IMPORTS, (
                    f"Disallowed import in client.py: {name.name}"
                )

        if isinstance(node, ast.ImportFrom):
            root = node.module.split(".")[0] if node.module else ""
            assert root in ALLOWED_IMPORTS, (
                f"Disallowed import-from in client.py: {node.module}"
            )
