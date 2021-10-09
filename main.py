import enumrate
import dns.resolver
import dnsresolver
import cname_attack
import dangling_ip
from urllib.parse import urlparse



def url2host(url):
    if ('http://') in url or ('https://') in url:
        url = urlparse(url)
        url = url.netloc.split(':')[0]
    if '/' in url:
        url = url.split('/')[0]
    if 'www' in url:
        url = url.split('www')[1][1:]
    if ':' in url:
        url = url.split(':')[0]
    return url

if __name__ == '__main__':
    dns.resolver.default_resolver = dnsresolver.get_resolver('8.8.8.8')
    host = url2host("https://dordali.xyz/")
    print("[-] Enumrating subdomains for host %s" % host)
    domains = set()
    domains = enumrate.enumrate_subdomains(host)
    domains.add(host)
    print(f"[-] Found %s subdomains" % len(domains))
    for domain in domains:
        print("[-] Checking Subdomain", domain)
        vul, ip = dangling_ip.is_vulnerable(domain)
        if vul:
            print('   [!] subdomain', domain, 'might have an EC2 dangling ip', ip)
        for cname in cname_attack.get_cname_records(domain):
            print('   [+] checking cname', cname)
            vuln, via = cname_attack.vulnerable_cname(domain, cname)
            if vuln and via != 'NXDOMAIN':
                print('   [!] subdomain', domain, 'takeoverable via', via, 'with CNAME', cname)
            elif vuln and via == 'NXDOMAIN':
                print('   [!] subdomain', domain, 'has an external, non-resolvable CNAME', cname)
