import pytest

from scripts import check_docs_frontmatter
from scripts import check_hardcoded_ips
from scripts import check_py36_compat


@pytest.mark.parametrize(
    "module",
    [
        check_docs_frontmatter,
        check_hardcoded_ips,
        check_py36_compat,
    ],
)
def test_resolve_repo_path_accepts_repository_file(module):
    path = module.resolve_repo_path(__file__)

    assert path == module.Path(__file__).resolve()


@pytest.mark.parametrize(
    "module",
    [
        check_docs_frontmatter,
        check_hardcoded_ips,
        check_py36_compat,
    ],
)
def test_resolve_repo_path_rejects_outside_file(module, tmp_path):
    outside_file = tmp_path / "outside.py"
    outside_file.write_text("pass\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside the repository"):
        module.resolve_repo_path(outside_file)
