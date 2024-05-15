from spf_record_validator import validate_spf


def test_redirect():
    assert validate_spf("v=spf1 redirect=ikea.com", "makrosystem.com")["status"]


def test_validates_exists_mechanism():
    assert validate_spf("v=spf1 exists:ikea.com -all", "ikea.com")["status"]
    assert not validate_spf("v=spf1 exists:com -all", "example.org")["status"]


def test_validates_include_mechanism():
    assert validate_spf("v=spf1 include:_spf.ikea.com -all", "ikea.com")["status"]
    assert validate_spf(
        "v=spf1 include:_spf.ikea.com -all", "spf.protection.outlook.com"
    )["status"]
    assert not validate_spf("v=spf1 include:_spf.ikeacom -all", "example.org")["status"]


def test_validates_a_mechanism():
    assert validate_spf("v=spf1 a -all", "ikea.com")["status"]
    assert not validate_spf("v=spf1 a/f::f -all", "ikea.com")["status"]


def test_validates_mx_mechanism():
    assert validate_spf("v=spf1 mx -all", "ikea.com")["status"]
    assert not validate_spf("v=spf1 mx:dasdas.asd -all", "ikea.com")["status"]


def test_validates_ip4_mechanism():
    assert validate_spf("v=spf1 ip4:192.0.2.0/24 -all", "ikea.com")["status"]
    assert not validate_spf("v=spf1 ip4:10.0.2.0/52 -all", "example.org")["status"]


def test_validates_ip6_mechanism():
    assert validate_spf("v=spf1 ip6:2001:db8::/32 -all", "ikea.com")["status"]
    assert not validate_spf("v=spf1 ip6:001:db8:::/764 -all", "example.org")["status"]


def test_validates_all_mechanism():
    assert not validate_spf("v=spf1 -all", "example.org")["status"]


def test_validates_redirect_mechanism():
    assert validate_spf("v=spf1 redirect=ikea.com", "makrosystem.com")["status"]
    assert not validate_spf(
        "v=spf1 redirect=ikea.com redirect=makrosystem.com", "ikea.com"
    )["status"]
