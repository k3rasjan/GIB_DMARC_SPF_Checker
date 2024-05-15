import dns.resolver
import re


# Helping functions
def throw_issue(severity: str, message: str, issues: list):
    issues.append({"severity": severity, "message": message})


def is_public_ip4(ip: str):

    # Check if it is an ipv4 address

    ip_regex = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(/(3[0-2]|[1-2][0-9]|[1-9]))?$"
    )

    if not ip_regex.match(ip):
        return False

    # Check if the IP address is public
    ip = ip.split(".")
    if ip[0] == "10":
        return False
    if ip[0] == "192" and ip[1] == "168":
        return False
    try:
        if ip[0] == "172" and 16 <= int(ip[1]) <= 31:
            return False
    except:
        return False
    return True


def is_ip6_valid(ip: str):
    # Check if it is an ipv6 address
    # helper variables
    double_colon = False
    omitting_zeros = False
    ip_regex = re.compile(r"[0-9a-f:]+(/(1[0-2][0-8]|[1-9][0-9]|[1-9]))?$")

    # Initial check of the syntax (characters and prefix length)
    if ip_regex.match(ip):
        ip = ip.split("/")[0]
        segments = ip.split(":")
        for index, segment in enumerate(segments):
            # Check for the zeros compression
            if segment == "":
                if double_colon:
                    if index != len(segments) - 1:
                        return False
                double_colon = True

            # Check the syntax for each segment
            elif re.match(r"^[0-9a-f]{1-4}$", segment):
                if len(segment) < 4:
                    omitting_zeros = True
                if omitting_zeros and segment.startswith("0"):
                    return False

        # TO DO Uni/Multi/Any cast check if it changes anything

        return True
    return False


def find_spf_record(domain: str, issues: list):
    # Find the SPF record for the provided domain
    try:
        records = dns.resolver.resolve(domain, "TXT")
        for record in records:
            record = str(record)
            if record.startswith("v=spf1"):
                validate_spf(record, domain, issues)
    except:
        throw_issue("critical", "No SPF record found", issues)


def find_a_record(domain: str, issues: list):
    # Find the A record for the provided domain
    a_redords = []
    try:
        records = dns.resolver.resolve(domain, "A")
        for record in records:
            record = str(record)
            a_redords.append(record)
    except:
        throw_issue("critical", "No A record found", issues)
    return a_redords


def find_mx_record(domain: str, issues: list):
    mx_records = []
    try:
        records = dns.resolver.resolve(domain, "MX")
        for record in records:
            record = str(record)
            mx_records.append(record)
    except:
        throw_issue("critical", "No MX record found", issues)
    return mx_records


def validate_spf(spf_record: str, curr_domain: str, issues: list = []):
    # Check if the SPF record is valid

    # helper variables
    all_check = False
    redirect_check = False
    issues = []
    test_status = True

    # Check if it is an spf record
    if spf_record.startswith("v=spf1"):
        if re.match(r"[A-Z]", spf_record):
            throw_issue(
                "critical",
                "Spf record should must not contain uppercase characters in it",
                issues,
            )
        # Split the record into items
        spf_record = spf_record.split(" ")
        spf_record.pop(0)
        # Iterate over the items
        for item in spf_record:
            # Check if there is no tags after all mechanism
            if all_check:
                throw_issue(
                    "critical",
                    "No mechanism should be used after all mechanism - then all mechanism is not evaluated",
                    issues,
                )

            # Check if the item is the all mechanism
            if item.endswith("all"):
                if redirect_check:
                    throw_issue(
                        "critical",
                        "all mechanism is used with redirect mechanism which should not be done",
                        issues,
                    )
                if all_check:
                    throw_issue(
                        "critical", "all mechanism is used more than once", issues
                    )
                if len(item) != 4:
                    throw_issue(
                        "critical", "all mechanism syntax must be [-+?~]all", issues
                    )
                if item.startswith("+") or item.startswith("?"):
                    throw_issue(
                        "warning",
                        "It is preffered for the all tag to be - or ~",
                        issues,
                    )
                all_check = True

            # Check if the item is the include mechanism
            elif item.startswith("include:"):
                include_domain = item.split(":")[1]
                find_spf_record(include_domain, issues)

            # Check if the item is the redirect mechanism
            elif item.startswith("redirect="):
                if redirect_check:
                    throw_issue(
                        "critical", "redirect mechanism is used more than once", issues
                    )
                redirect_domain = item.split("=")[1]
                find_spf_record(redirect_domain, issues)
                redirect_check = True

            # Check if the item is the ip4 mechanism
            elif item.startswith("ip4:"):
                ip = item.split(":")[1]
                if not is_public_ip4(ip):
                    throw_issue(
                        "warning",
                        f"The ip address: {ip} is not a public ipv4 address",
                        issues,
                    )

            # Check if the item is the ip6 mechanism
            elif item.startswith("ip6:"):
                ip = item.split(":")[1]
                if not is_ip6_valid(ip):
                    throw_issue("critical", f"Invalid ipv6 address: {ip}", issues)

            # Check if the item is the a mechanism
            elif item.startswith("a"):
                # TO DO: Add support for a with no arguments
                if item == "a":
                    a_records = find_a_record(curr_domain, issues)
                    for record in a_records:
                        if not is_public_ip4(record):
                            throw_issue(
                                "warning",
                                f"The ip address: {record} from the A record of the domain: {curr_domain} is not a public ipv4 address",
                                issues,
                            )
                elif item.startswith("a:"):
                    domain = item.split(":")[1]
                    if len(domain.split("/")) > 2:
                        throw_issue(
                            "error",
                            f"Invalid value:{domain} for the A mechanism, it should be a[:domain][/prefix]",
                            issues,
                        )
                    elif len(domain.split("/")) > 1 and not re.match(
                        r"^(/(3[0-2]|[1-2][0-9]|[1-9]))$", domain.split("/")[1]
                    ):
                        throw_issue(
                            "error", "Invalid prefix length in the A mechanism", issues
                        )
                    else:
                        domain = domain.split("/")[0]

                        a_records = find_a_record(domain, issues)
                        for record in a_records:
                            if not is_public_ip4(record):
                                throw_issue(
                                    "warning",
                                    f"The ip address: {record} from the A record of the provided domain: {domain} is not a public ipv4 address",
                                    issues,
                                )
                # Not sure how to know if there would be an ipv4 or ipv6 address though it is easily rewritable to support both
                elif item.startswith("a/"):
                    prefix = item.split("/")[1]
                    if not re.match(r"^(/(3[0-2]|[1-2][0-9]|[1-9]))$", prefix):
                        throw_issue(
                            "error", "Invalid prefix length in the A mechanism", issues
                        )
                    a_records = find_a_record(curr_domain, issues)
                    for record in a_records:
                        if not is_public_ip4(record):
                            throw_issue(
                                "warning",
                                f"The ip address: {record} from the A record of the current domain: {curr_domain} is not a public ipv4 address",
                                issues,
                            )

            #  Check if the item is the mx mechanism
            elif item.startswith("mx"):
                if item == "mx":
                    mx_records = find_mx_record(curr_domain, issues)
                    for mx_record in mx_records:
                        a_records = find_a_record(mx_record.split(" ")[1], issues)
                        for a_record in a_records:
                            if not is_public_ip4(a_record):
                                throw_issue(
                                    "warning",
                                    f"The ip address: {a_record} from the MX record of the current domain: {curr_domain} is not a public ipv4 address",
                                    issues,
                                )
                elif item.startswith("mx:"):
                    domain = item.split(":")[1]
                    if len(domain.split("/")) > 2:
                        throw_issue(
                            "error",
                            f"Invalid value:{domain} for the A mechanism, it should be a[:domain][/prefix]",
                            issues,
                        )
                    elif len(domain.split("/")) > 1 and not re.match(
                        r"^(/(3[0-2]|[1-2][0-9]|[1-9]))$", domain.split("/")[1]
                    ):
                        throw_issue(
                            "error", "Invalid prefix length in the A mechanism", issues
                        )
                    else:
                        domain = domain.split("/")[0]
                        mx_records = find_mx_record(domain, issues)
                        for mx_record in mx_records:
                            a_records = find_a_record(mx_record.split(" ")[1], issues)
                            for a_record in a_records:
                                if not is_public_ip4(a_record):
                                    throw_issue(
                                        "warning",
                                        f"The ip address: {record} from the MX record of the provided domain: {domain} is not a public ipv4 address",
                                        issues,
                                    )
                elif item.startswith("mx/"):
                    prefix = item.split("/")[1]
                    if not re.match(r"^(/(3[0-2]|[1-2][0-9]|[1-9]))$", prefix):
                        throw_issue(
                            "error", "Invalid prefix length in the A mechanism", issues
                        )
                    mx_records = find_mx_record(curr_domain, issues)
                    for mx_record in mx_records:
                        a_records = find_a_record(mx_record.split(" ")[1], issues)
                        for a_record in a_records:
                            if not is_public_ip4(a_record):
                                throw_issue(
                                    "warning",
                                    f"The ip address: {record} from the MX record of the current domain: {curr_domain} is not a public ipv4 address",
                                    issues,
                                )

            # Check if the item is the exists mechanism
            elif item.startswith("exists:"):
                domain = item.split(":")[1]
                if not len(find_a_record(domain, issues)) > 0:
                    throw_issue(
                        "warning",
                        f"Domain provided in exists mehcanism: {domain} is not a match or is not valid",
                        issues,
                    )

            # Check if the item is the ptr mechanism
            elif item.startswith("ptr"):
                throw_issue("warning", "ptr mechanism should not be published", issues)

            else:
                throw_issue("critical", f"Invalid mechanism: {item}", issues)

    else:
        throw_issue("critical", "Provided string is not an SPF record", issues)

    if len(issues) > 0:
        test_status = False
    return {"status": test_status, "issues": issues}
