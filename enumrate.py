import sublist3r
import requests

def sublist3r_enumeration(hostname):
    subdomains = sublist3r.main(hostname, 40, '', ports=None, silent=True, verbose=False,
                                enable_bruteforce=False, engines=None)
    return set(subdomains)

def crt_enumrate(hostname):
    domains = set()
    certUrl = 'https://crt.sh/?q=' + hostname + '&output=json'
    try:
        response = requests.get(certUrl).json()
    except:
        print("Error collecting domains from certificate transparency")
        return domains
    for cert in response:
        domains.add(cert['common_name'])
        if '\n' in cert['name_value'] :
            domains.update(cert['name_value'].split())
        else:
            domains.add(cert['name_value'])
    return domains

def remove_wildcards(domains):
    subdomains = domains.copy()
    for domain in domains:
        if '*' in domain:
            subdomains.remove(domain)
            subdomains.add(domain.split('*')[1][1:])
    return subdomains

def enumrate_subdomains(hostname):
    domains = set()
    domains.update(crt_enumrate(hostname))
    domains.update(sublist3r_enumeration(hostname))
    domains = remove_wildcards(domains)
    return domains
