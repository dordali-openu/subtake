import random
import socket
import dns.resolver
from cname_attack import *
import structs
import requests
import tld


def create_resolver(resolvers):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = resolve_all_names(resolvers if isinstance(resolvers, list) else [resolvers])
    return resolver


def get_resolver(resolver):
    if isinstance(resolver, str) or isinstance(resolver, list):
        return create_resolver(resolver)
    elif not resolver:
        return dns.resolver
    return resolver


def get_a_records(name, resolver=None):
    try:
        return [str(answer) for answer in get_resolver(resolver).resolve(name)]
    except:
        return []



def resolve_all_names(names, resolver=None):
    resolved = []
    for name in names:
        resolved += [name] if is_ip(name) else get_a_records(name, resolver)
    return resolved


def is_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False


def reason(name, resolver=None, rdtype='A'):
    try:
        get_resolver(resolver).query(name, rdtype)
    except Exception as e:
        return e
    return None

def can_resolve_name(name, resolver=None):
    return len(get_a_records(name, resolver)) > 0



def tld_plus_one(name):
    suffix = tld.get_tld(name, fix_protocol=True)
    name = name[:-len(suffix)-1]
    if '.' in name:
        name = name[name.rindex('.')+1:]
    return name + '.' + suffix


def same_tld_plus_one(name1, name2):
    try:
        return tld_plus_one(name1) == tld_plus_one(name2)
    except:
        return False

def get_content(domain):
    try:
        return requests.get('https://'+domain, verify=False).text
    except:
        try:
            return requests.get('http://'+domain, verify=False).text
        except:
            pass
    return ''





