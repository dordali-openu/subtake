import requests
import ipaddress
import dnsresolver

ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['prefixes']
amazon_ips = [item['ip_prefix'] for item in ip_ranges if item["service"] == "EC2"]


def is_aws_ip(ip):
    for ip_range in amazon_ips:
        if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(ip_range):
            return True
    return False

def is_alive(host):
    try:
        return requests.get('https://'+host, verify=False, timeout=0.5).text
    except:
        try:
            return requests.get('http://'+host, verify=False, timeout=0.5).text
        except:
            return False

def is_vulnerable(host):
    try:
        for ip in dnsresolver.get_a_records(host):
            if is_aws_ip(ip) and not is_alive(host):
                return True, ip
        return False,0
    except:
        return False
