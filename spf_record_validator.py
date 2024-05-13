import dns.resolver
import re

#Helping functions
def throw_issue(severity: str, message: str, issues: list):
    issues.append({"severity": severity, "message": message})

def is_ip4_public(ip):

    #Check if it is an ip

    ip_regex = re.compile(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(/(3[0-2]|[1-2][0-9]|[1-9]))?$")

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


def find_spf_record(domain: str, issues: list):
    # Find the SPF record for the provided domain
    try:
        records = dns.resolver.resolve(domain, 'TXT')
        for record in records:
            record = str(record)
            if record.startswith("v=spf1"):
                validate_spf(record, issues)
    except:
        throw_issue("critical", "No SPF record found", issues)

def find_a_record(domain: str, issues: list):
    # Find the A record for the provided domain
    a_redords = []
    try:
        records = dns.resolver.resolve(domain, 'A')
        for record in records:
            record = str(record)
            a_redords.append(record)
        return a_redords
    except:
        throw_issue("critical", "No A record found", issues)

def validate_spf(spf_record: str, issues: list = []):
    # Check if the SPF record is valid

    # helper variables
    all_check = False
    redirect_check = False
    issues = []
    test_status = True
    
    # Check if it is an spf record
    if spf_record.startswith("v=spf1"):
        # Split the record into items
        spf_record = spf_record.split(" ")
        spf_record.pop(0)
        # Iterate over the items
        for item in spf_record:
            # Check if the item is the all mechanism
            if item.endswith("all"):
                if redirect_check:
                    throw_issue("critical", "all mechanism is used with redirect mechanism which should not be done", issues)
                if all_check:
                    throw_issue("critical", "all mechanism is used more than once", issues)
                if len(item) != 4:
                    throw_issue("critical", "all mechanism syntax must be [-+?~]all", issues)
                if item.startswith("+") or item.startswith("?"):
                    throw_issue("warning", "all mechanism should be prefixed with - or ~", issues)
                all_check = True
            # Check if the item is the include mechanism
            elif item.startswith("include:"):
                include_domain = item.split(":")[1]
                find_spf_record(include_domain, issues)

            # Check if the item is the redirect mechanism    
            elif item.startswith("redirect="):
                if redirect_check:
                    throw_issue("critical", "redirect mechanism is used more than once", issues)
                if all_check:
                    throw_issue("critical", "redirect mechanism is used after all mechanism", issues)
                redirect_domain = item.split("=")[1]
                find_spf_record(redirect_domain, issues)
                redirect_check = True

            elif item.startswith("ip4:"):
                ip = item.split(":")[1]
                if not is_ip4_public(ip):
                    throw_issue("warning", f"The ip address: {ip} is not a public ipv4 address", issues)
            
            #TO DO: Add support for ipv6 mechanism
            elif item.startswith("ip6:"):
                #ipv6 not yet supported
                throw_issue("low", "IPv6 is not yet supported", issues)

            elif item.startswith("a"):
                #TO DO: Add support for a with no arguments
                if item == "a":
                    throw_issue("low", "a with no arguments is not yet supported", issues)
                if item.startswith("a:"):
                    domain = item.split(":")[1]
                    a_records = find_a_record(domain, issues)
                    for record in a_records:
                        if not is_ip4_public(record):
                            throw_issue("warning", f"The ip address: {record} from A mechanism is not a public ipv4 address", issues)
                #TO DO: Add support for a/ mechanism
                elif item.startswith("a/"):
                    throw_issue("low", "a/ mechanism is not yet supported", issues)

            else:
                throw_issue("critical", f"Unknown mechanism: {item}", issues)

    else:
        throw_issue("critical", "Provided string is not an SPF record", issues)

    if len(issues) > 0:
        test_status = False
    return {"status": test_status, "issues": issues}

valid_spf = "v=spf1 a:group-ib.ru include:_spf.google.com ?all redirect:google.com"

result = validate_spf(valid_spf)

print(result['status'])
for issue in result['issues']:
    print(issue)