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
        test_status = False
        return {"status": test_status, "issues": issues}

    user_tags = [tag.strip() for tag in record.split(";")]
    user_tags.pop(0)
    user_tags.pop(-1)

    for tag in user_tags:
        validate_tag(tag, issues, domain)
    if len(issues) > 0:
        test_status = False
    return {"status": test_status, "issues": issues}


# Validating tags
def validate_tag(argument: str, issues: list, domain: str):
    tag = argument.split("=")[0]
    if len(argument.split("=")) > 1:
        value = argument.split("=")[1]


    tag_rules = {
        "p": ["none", "quarantine", "reject"],
        "sp": ["none", "quarantine", "reject"],
        "rua": ["email"],
        "ruf": ["email"],
        "fo": ["0", "1", "d", "s"],  # list
        "adkim": ["s", "r"],
        "aspf": ["s", "r"],
        "rf": ["afrf"],
        "ri": "32-bit unsigned integer",
        "pct": [0, 100],
    }

    if tag not in tag_rules.keys():
        throw_issue("error", f"Invalid tag: {tag}", issues)
        return issues

    match tag:
        case "ri":
            try:
                value = int(value)
            except:
                throw_issue(
                    "error", "ri tag value must be a 32-bit unsigned integer", issues
                )
            else:
                if value < 0 or value > 4294967295:
                    throw_issue(
                        "error", "ri tag value is not a 32-bit unsigned integer", issues
                    )

        case "pct":
            try:
                value = int(value)
            except:
                throw_issue(
                    "error",
                    "pct tag value must be an integer between 0 and 100 prefferably 100",
                    issues,
                )
            else:
                if value < 0 or value > 100:
                    throw_issue(
                        "error",
                        "pct tag value must be between 0 and 100 prefferably 100",
                        issues,
                    )
                elif value < 100:
                    throw_issue(
                        "warning", "It is safer if pct tag value is set to 100", issues
                    )

        case "fo":
            values = value.split(":")
            used_values = []
            for value in values:
                if value not in tag_rules["fo"]:
                    throw_issue("error", f"Invalid value: {value} in fo tag it should be one of: {tag_rules["fo"]}", issues)
                else:
                    if value in used_values:
                        throw_issue("error", f"Duplicate value in fo tag", issues)
                    used_values.append(value)


        # TO DO: Fix this code, make it explain why the email is invalid

        case "rua" | "ruf":
            mails = value.split(",")
            for mail in mails:
                if not mail.startswith("mailto:"):
                    throw_issue("error", f"Invalid email in {tag} tag", issues)
                else:
                    mail = mail.replace("mailto:", "")
                    if not "@" in mail:
                        throw_issue("error", f"Invalid email in {tag} tag", issues)
                    else:
                        mail = mail.split("@")
                        if len(mail) != 2:
                            throw_issue(
                                "error", f"Invalid email in {tag} tag", issues
                            )
                        else:
                            if mail[1].startswith("."):
                                throw_issue(
                                    "error",
                                    f"Invalid email in {tag} tag. Domain should not start with a .",
                                    issues,
                                )
                            elif mail[0].endswith(".") or mail[0].startswith("."):
                                throw_issue(
                                    "error",
                                    f"Invalid email in {tag} tag. Mail should not start nor  end with a .",
                                    issues,
                                )
                            elif mail[0].find("..") > 0:
                                throw_issue(
                                    "error",
                                    f"Invalid email in {tag} tag. Mail should not include ..",
                                    issues,
                                )
                        if not validate_domain(mail[1], domain):
                            throw_issue(
                                "error",
                                f"Email: {mail[1]} provided in {tag} tag does not accept reports from your domain or is invalid.",
                                issues,
                            )

        case _:
            if value not in tag_rules[tag]:
                rule = tag_rules[tag][0]
                rules = f"{rule}"
                for i in range(1, len(tag_rules[tag])):
                    rules += " or " + tag_rules[tag][i]

                throw_issue("error", f"Tag {tag} value must be {rules}", issues)
            if tag == "p" or tag == "sp":
                if value == "none":
                    throw_issue(
                        "warning",
                        f"Tag {tag} is set to none. It is recommended to set it to quarantine or reject",
                        issues,
                    )
