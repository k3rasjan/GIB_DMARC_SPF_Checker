from spf_record_validator import validate_spf


def test_validates_correct_input():
    assert validate_spf(
        "v=spf1 include:_spf.ikea.com include:spf.protection.outlook.com -all",
        "ikea.com",
    )["status"]


def test_doesnt_validate_bad_input():
    assert not validate_spf(
        "v=spf1 include:_spf.ikea.com include:spf.protection.outlook.com -all asd",
        "ikea.com",
    )["status"]


def test_():
    assert validate_spf("v=spf1 redirect=ikea.com", "makrosystem.com")["status"]
