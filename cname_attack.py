import structs
import dnsresolver
import requests


def get_cname_records(name, resolver=None):
    try:
        for answer in dnsresolver.get_resolver(resolver).resolve(name, 'CNAME'):
            cname = str(answer.target)[:-1]
            yield cname
            yield from get_cname_records(cname, resolver)
    except:
        pass


def get_content(domain):
    try:
        return requests.get('https://'+domain, verify=False, timeout=0.5).text
    except:
        try:
            return requests.get('http://'+domain, verify=False, timeout=0.5).text
        except:
            pass
    return ''


def vulnerable_cname(domain, cname, dns_only=False):

    resolveable = dnsresolver.can_resolve_name(cname)

    content = get_content(domain)
    if resolveable and not dns_only:
        if cname.endswith(structs.FASTLY_SUFFIX) and 'Fastly error: unknown domain:' in get_content(domain):
            return True, 'Fastly'

        if cname.endswith(structs.CF_SUFFIX) and '404 Not Found: Requested route (\'' in get_content(domain):
            return True, 'CloudFoundry'

        if cname.endswith(structs.HEROKU_SUFFIX) and 'nothing here, yet.' in get_content(domain):
            return True, 'Heroku'

        if cname.endswith(structs.AMAZONSAWS) and 's3' in cname and 'NoSuchBucket' in get_content(domain):
            return True, 'AmazonS3'

        if cname.endswith(structs.GITHUB_IO_SUFFIX) and 'There isn\'t a GitHub Pages site here' in get_content(domain):
            return True, 'github.io'

        if cname.endswith(structs.README_IO_SUFFIX) and 'Project doesnt exist...' in get_content(domain):
            return True, 'readme.io'

        if cname.endswith(structs.CARGO_COLLECTIVE_SUFFIX) and '404 Not Found' in get_content(domain):
            return True, 'Cargo'

        if cname.endswith(structs.CAMPAIGN_MONITOR_SUFFIX) and 'Trying to access your account' in get_content(domain):
            return True, 'CampaignMonitor'

        if cname.endswith(structs.FEEDPRESS_SUFFIX) and 'The feed has not been found' in get_content(domain):
            return True, 'FeedPress'

        if cname.endswith(structs.INTERCOM_SUFFIX) and 'Uh oh. That page doesn\'t exist.' in get_content(domain):
            return True, 'Intercom'

        if cname.endswith(structs.STRIKINGLY_SUFFIX) and 'page not found' in get_content(domain):
            return True, 'Strikingly'

        if cname.endswith(structs.SURGESH_SUFFIX) and 'project not found' in get_content(domain):
            return True, 'Surge.sh'

        if cname.endswith(structs.UPTIMEROBOT_SUFFIX) and 'page not found' in get_content(domain):
            return True, 'UptimeRobot'

        if '404 Blog is not found' in content:
            return True, 'HatenaBlog'

        if 'The thing you were looking for is no longer here, or never was' in content:
            return True, 'Ghost'

        if 'No settings were found for this company' in content:
            return True, 'HelpScout'

        if 'No Site For Domain' in content:
            return True, 'Kinsta'

        if 'It looks like you may have taken a wrong turn somewhere.' in content:
            return True, 'LaunchRock'

        if '404 error unknown site!' in content:
            return True, 'Pantheon'

        if 'Whatever you were looking for doesn\'t currently exist at this address' in content:
            return True, 'Tumblr'

        if 'This UserVoice subdomain is currently available!' in content:
            return True, 'UserVoice'

        if 'Do you want to register' in content:
            return True, 'Wordpress.com'

        if '404 Not Found: Requested route (\'' in content:
            return True, 'CloudFoundry'

    if cname.endswith(structs.AZURE_SUFFIX) and not dnsresolver.can_resolve_name(cname):
        return True, 'Azure'

    if (not resolveable) and ns_attack.vulnerable_nameserver(cname)[0]:
        return True, 'cloud DNS'

    if (not resolveable) and (not dnsresolver.same_tld_plus_one(domain, cname)):
        return True, 'NXDOMAIN'

    return False, ''