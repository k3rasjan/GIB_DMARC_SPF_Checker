from dmarc_syntaxchecker import validate_dmarc


def test_validate_dmarc_valid():
    # Test case for a valid DMARC record
    dmarc_record = "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc_rua@group-ib.tech; ruf=mailto:dmarc_ruf@group-ib.tech; fo=1; adkim=r; aspf=r;"
    assert validate_dmarc(dmarc_record, "group-ib.com")["status"]


def test_validate_dmarc_invalid():
    # Test case for an invalid DMARC tag
    dmarc_record = "v=DMARC1; p=none; foobar=invalid"
    assert not validate_dmarc(dmarc_record, "group-ib.com")["status"]


def test_validate_dmarc_missing_required_fields():
    # Test case for missing required fields in DMARC record
    dmarc_record = "v=DMARC1; p=none;"
    assert not validate_dmarc(dmarc_record, "group-ib.com")["status"]


def test_validate_dmarc_multiple_policies():
    # Test case for multiple policies in DMARC record
    dmarc_record = "v=DMARC1; p=none; p=quarantine"
    assert not validate_dmarc(dmarc_record, "group-ib.com")["status"]


def test_validate_dmarc_invalid_policy_value():
    # Test case for an invalid policy value in DMARC record
    dmarc_record = "v=DMARC1; p=invalid"
    assert not validate_dmarc(dmarc_record, "group-ib.com")["status"]


def test_validate_dmarc_invalid_rua_value():
    # Test case for an invalid rua value in DMARC record
    dmarc_record = "v=DMARC1; p=none; rua=invalid"
    assert not validate_dmarc(dmarc_record, "group-ib.com")["status"]
