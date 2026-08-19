from invariant.assessment import document_slug_for_os


def test_document_slug_for_debian():
    assert document_slug_for_os("debian", "11") == "debian_linux_11"


def test_document_slug_for_ubuntu_replaces_dot_with_underscore():
    assert document_slug_for_os("ubuntu", "20.04") == "ubuntu_linux_20_04"
