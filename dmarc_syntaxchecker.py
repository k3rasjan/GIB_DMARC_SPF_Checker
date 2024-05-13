import dns.resolver


# Helping functions
def throw_issue(severity: str, message: str, issues: list):
    issues.append({"severity": severity, "message": message})


def validate_domain(host_portion: str, domain: str):

    check = False

    if host_portion == domain:
        return True

    host_portion = domain + "._report._dmarc." + host_portion

    try:
        text_record = dns.resolver.resolve(host_portion, "txt")
    except:
        return False
    else:
        for record in text_record:
            record = str(record)
            if record.find("v=DMARC1") > 0:
                check = True

    # could ask server if email name exists but not optimal and not always important

    return check


# Validating DMARC record
def validate_dmarc(record: str, domain: str):
    issues = []
    test_status = True

    if not record.startswith("v=DMARC1"):
        throw_issue("critical", "DMARC record does not start with v=DMARC1", issues)

    user_tags = [tag.strip() for tag in record.split(";")]
    user_tags.pop(0)
    user_tags.pop(-1)

    for tag in user_tags:
        validate_tag(tag, issues, domain)
    if len(issues) > 0:
        test_status = False
    return {"status": test_status, "issues": issues}


# Validating tags
def validate_tag(tag: str, issues: list, domain: str):
    valid_tags = ["p", "sp", "rua", "ruf", "fo", "adkim", "aspf", "rf", "ri", "pct"]
    tag = tag.split("=")

    if tag[0] not in valid_tags:
        throw_issue("error", f"Invalid tag: {tag[0]}", issues)
        return issues

    tag_rules = {
        "p": ["none", "quarantine", "reject"],
        "sp": ["none", "quarantine", "reject"],
        "rua": ["email"],
        "ruf": ["email"],
        "fo": [0, 1, "d", "s"],  # list
        "adkim": ["s", "r"],
        "aspf": ["s", "r"],
        "rf": ["afrf"],
        "ri": "32-bit unsigned integer",
        "pct": [0, 100],
    }

    match tag[0]:
        case "ri":

            try:
                tag[1] = int(tag[1])
            except:
                throw_issue(
                    "error", "ri tag value must be a 32-bit unsigned integer", issues
                )
            else:
                if tag[1] < 0 or tag[1] > 4294967295:
                    throw_issue(
                        "error", "ri tag value is not a 32-bit unsigned integer", issues
                    )

        case "pct":
            try:
                tag[1] = int(tag[1])
            except:
                throw_issue("error", "pct tag value must be an integer", issues)
            else:
                if tag[1] < 0 or tag[1] > 100:
                    throw_issue(
                        "error", "pct tag value must be between 0 and 100", issues
                    )
                elif tag[1] < 100:
                    throw_issue(
                        "warning", "It is safer if pct tag value is set to 100", issues
                    )

        case "fo":
            values = tag[1].split(":")
            for value in values:
                if value not in ["0", "1", "d", "s"]:
                    throw_issue("error", "Invalid value in fo tag", issues)

        # TO DO: Fix this code, make it explain why the email is invalid

        case "rua" | "ruf":
            mails = tag[1].split(",")
            for mail in mails:
                if not mail.startswith("mailto:"):
                    throw_issue("error", f"Invalid email in {tag[0]} tag", issues)
                else:
                    mail = mail.replace("mailto:", "")
                    if not "@" in mail:
                        throw_issue("error", f"Invalid email in {tag[0]} tag", issues)
                    else:
                        mail = mail.split("@")
                        if len(mail) != 2:
                            throw_issue(
                                "error", f"Invalid email in {tag[0]} tag", issues
                            )
                        else:
                            if mail[1].startswith("."):
                                throw_issue(
                                    "error",
                                    f"Invalid email in {tag[0]} tag. Domain should not start with a .",
                                    issues,
                                )
                            elif mail[0].endswith(".") or mail[0].startswith("."):
                                throw_issue(
                                    "error",
                                    f"Invalid email in {tag[0]} tag. Mail should not start nor  end with a .",
                                    issues,
                                )
                            elif mail[0].find("..") > 0:
                                throw_issue(
                                    "error",
                                    f"Invalid email in {tag[0]} tag. Mail should not include ..",
                                    issues,
                                )
                        if not validate_domain(mail[1], domain):
                            throw_issue(
                                "error",
                                f"Email: {mail[1]} provided in {tag[0]} tag does not accept reports from your domain or is invalid.",
                                issues,
                            )

        case _:
            if tag[1] not in tag_rules[tag[0]]:
                rules = f"{tag_rules[tag[0]][0]}"
                for i in range(1, len(tag_rules[tag[0]])):
                    rules += " or " + tag_rules[tag[0]][i]

                throw_issue("error", f"Tag {tag[0]} value must be {rules}", issues)
            if tag[0] == "p" or tag[0] == "sp":
                if tag[1] == "none":
                    throw_issue(
                        "warning",
                        f"Tag {tag[0]} is set to none. It is recommended to set it to quarantine or reject",
                        issues,
                    )


valid_dmarc = "v=DMARC1;pct=100;p=quarantine;sp=quarantine;pct=100;adkim=s;aspf=s;rua=mailto:re+utmxvyjdosi@dmarc.postmarkapp.com,mailto:easy58d26@easydmarc.com,mailto:alerts@makrosystem.com,mailto:sdaasd@dasdsa.pl;ruf=mailto:ruf@rep.easydmarc.com,mailto:alerts@makrosystem.com;"

result = validate_dmarc(valid_dmarc, "makrosystem.com")

print(result["status"])
for issue in result["issues"]:
    print(issue)
