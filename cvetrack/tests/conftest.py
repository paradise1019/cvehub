import pytest


@pytest.fixture(autouse=True)
def cvetrack_settings(settings, tmp_path):
    settings.CVETRACK = {"DATA_DIR": str(tmp_path / "data"), "UBUNTU_RELEASES": ["24.04"], "OSV_MIN_ROWS_PER_RELEASE": 1,
                         "PRO_MODE": "auto", "INCLUDE_UNFIXED": False, "CHECK_OLD_KERNELS": False, "KERNEL_API_URL": "",
                         "HOST_SOURCE": "landscape", "IMPORT_BATCH": 3}
    return settings
