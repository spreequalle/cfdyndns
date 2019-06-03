# provide dyndns update url for cloudflare utilizing aws lambda
# Update URL example:
# https://help.dyn.com/remote-access-api/perform-update
# 2019 Erik Hoppe <ErikHoppe@web.de>

from botocore.vendored import requests
import ipaddress
import re


# validate and receive ip address
def getip_address(address, version):

    ip = ipaddress.ip_address(address)
    if ip.version != version:
        raise ValueError()
    return ip


# validate domain
def validate_domain(domain):

    # stolen from: https://validators.readthedocs.io
    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    if not pattern.match(domain):
        raise ValueError(str(domain) + ', is not a valid domain.')
    return domain


# set zone A/AAAA records
def set_record(cf_email, cf_apikey, zone, ip):

    # choose record type
    if ip.version == 4:
        rt = 'A'
    else:
        rt = 'AAAA'

    cf_ttl = 1 # 60 sec. ttl seems commonn for dyndns provider, but 120 sec is cf minimum, leaving it to auto.

    # cloudflare v4 api
    cf_api = 'https://api.cloudflare.com/client/v4/'
    cf_header = {'Content-Type': 'application/json',  'X-Auth-Email': cf_email, 'X-Auth-Key': cf_apikey}

    # get cloudflare zone id
    r = requests.get(cf_api + 'zones', headers=cf_header, params={'status': 'active', 'name': zone})
    zone_id = r.json()['result'][0]['id']

    # get existing a-records
    r = requests.get(cf_api + 'zones/' + zone_id + '/dns_records', headers=cf_header, params={'type': rt, 'name': zone})
    entries = r.json()['result']

    if len(entries) == 0:
        # create (initial) record
        r = requests.post(
            cf_api + 'zones/' + zone_id + '/dns_records', headers=cf_header,
            json={'type': rt, 'name': zone, 'content': ip.exploded, 'proxied': False, 'ttl': cf_ttl })
    else:
        # searching for additional records
        for record in entries[1:]:
            # deleting additional records
            requests.delete(cf_api + 'zones/' + zone_id + '/dns_records/' + record['id'], headers=cf_header)

        # update (existing) record
        r = requests.put(cf_api + 'zones/' + zone_id + '/dns_records/' + entries[0]['id'],
            headers=cf_header, json={'type': rt, 'name': zone, 'content': ip.exploded, 'proxied': False, 'ttl': cf_ttl })


def lambda_handler(event, context):
    try:

        # handle params
        parm = event['queryStringParameters']

        # cloudflare credentials
        cf_email = parm['cf_email']
        cf_apikey = parm['cf_apikey']

        domain = validate_domain(parm['domain'])

        # ipv4
        ipv4 = getip_address(parm['ipv4'], 4)
        set_record(cf_email, cf_apikey, domain, ipv4)

        # ipv6 (optional)
        if 'ipv6' in parm and parm['ipv6']:
            ipv6 = getip_address(parm['ipv6'], 6)
            set_record(cf_email, cf_apikey, domain, ipv6)

        return {
            'statusCode': 200,
            'body': 'Success!'
        }

    except ValueError as e:
        return {
            'statusCode': 400,
            'body': 'Error reading values!\n' + str(e)
        }

    except Exception as e:
        return {
            'statusCode': 400,
            'body': 'Something went wrong!\n' + str(e)
        }
