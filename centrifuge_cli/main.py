#!/usr/bin/env python3

import os
import sys
import json
import math
import uuid
import click
import requests
import dateparser
import pandas as pd

from datetime import datetime
from collections.abc import MutableMapping
from urllib.parse import urlparse, urlunparse
from centrifuge_cli.policy import CentrifugePolicyCheck
from centrifuge_cli.stats import CentrifugeStats
from centrifuge_cli import __version__ as PACKAGE_VERSION


pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 2000)
pd.set_option('display.float_format', '{:20,.2f}'.format)
pd.set_option('display.max_colwidth', 128)


def flatten(d, parent_key='', sep='.'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, MutableMapping):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


class Cli(object):

    def __init__(self, endpoint, apikey, limit, outfmt, fields, ssl_no_verify):
        self.apikey = apikey
        self.limit = limit
        self.outfmt = outfmt
        self.fields = fields
        self.echo_enabled = True

        url = urlparse(endpoint)
        self.endpoint_scheme = url.scheme
        self.endpoint_netloc = url.netloc

        self.ssl_verify = not(ssl_no_verify)

    def build_url(self, path, query_list, limit):
        # vulnerable-files does not properly support the limit parameter :facepalm:
        if ('vulnerable-files' in path):
            limit = 100
        default_query = [f'limit={limit}',
                         f'authtoken={self.apikey}']
        if query_list is not None:
            default_query.extend(query_list)

        query = '&'.join(default_query)
        return urlunparse((self.endpoint_scheme, self.endpoint_netloc, path, None, query, None))

    def do_GET(self, path, query_list=None, paginated=False):
        # handle paginated queries
        if paginated:
            results = []
            total = 0
            page = 1
            base_query_list = query_list if query_list else []
            while True:
                updated_query_list = base_query_list + [f'page={page}']
                url = self.build_url(path, updated_query_list, 100)
                try:
                    res = requests.get(url, verify=self.ssl_verify)
                    res.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    if res.status_code == 403:
                        self.echo(f'Access Denied (url: {url})', err=True)
                        sys.exit(-1)
                    else:
                        raise SystemExit(err)

                data = res.json()
                # handle binary hardness specifically while that API endpoint is not compliant with the rest :facepalm:
                data = data['checkSecs'] if 'checkSecs' in data else data
                results.extend(data['results'])
                count = data['count']
                total += len(data['results'])
                page += 1

                if total >= count or (self.limit > -1 and total >= self.limit):
                    break

            return json.dumps({'count': total, 'results': results}, indent=2, sort_keys=True)

        else:
            url = self.build_url(path, query_list, self.limit)
            try:
                res = requests.get(url, verify=self.ssl_verify)
                res.raise_for_status()
            except requests.exceptions.HTTPError as err:
                if res.status_code == 403:
                    self.echo(f'Access Denied (url: {url})', err=True)
                    sys.exit(-1)
                else:
                    raise SystemExit(err)

            data = res.json()
            data = data['checkSecs'] if 'checkSecs' in data else data

        if self.outfmt == 'json':
            return json.dumps(data, indent=2, sort_keys=True)

        results = data
        if 'results' in results:
            results = results['results']
        elif not isinstance(results, list):
            results = [results, ]
        flattened = []
        for r in results:
            flattened.append(flatten(r))

        df = pd.read_json(json.dumps(flattened))
        if len(self.fields) > 0 and len(df) > 0:
            df = df[list(self.fields)]

        if self.outfmt == 'csv':
            return df.to_csv()

        return df

    def do_POST(self, path, data, files=None, query_list=None):
        url = self.build_url(path, query_list, self.limit)
        try:
            res = requests.post(url, data=data, files=files)
            res.raise_for_status()
        except requests.exceptions.HTTPError as err:
            if res.status_code == 403:
                self.echo(f'Access Denied (url: {url})', err=True)
                sys.exit(-1)
            else:
                raise SystemExit(err)

        return res

    def do_PUT(self, path, data, query_list=None):
        url = self.build_url(path, query_list, self.limit)
        try:
            res = requests.put(url, data=data)
            res.raise_for_status()
        except requests.exceptions.HTTPError as err:
            if res.status_code == 403:
                self.echo(f'Access Denied (url: {url})', err=True)
                sys.exit(-1)
            else:
                raise SystemExit(err)

        return res

    def do_DELETE(self, path, query_list=None):
        url = self.build_url(path, query_list, self.limit)
        try:
            res = requests.delete(url)
            res.raise_for_status()
        except requests.exceptions.HTTPError as err:
            if res.status_code == 403:
                self.echo(f'Access Denied (url: {url})', err=True)
                sys.exit(-1)
            else:
                raise SystemExit(err)

        return('Deleted')

    def echo(self, message, err=False):
        if self.echo_enabled or err is True:
            click.echo(message, err=err)


pass_cli = click.make_pass_decorator(Cli)


@click.group()
@click.option('--endpoint', envvar='CENTRIFUGE_URL',
              default='https://centrifuge.refirmlabs.com', metavar='URL', help='Base URL for Centrifuge server')
@click.option('--apikey', envvar='CENTRIFUGE_APIKEY', required=True,
              metavar='KEY', help='Your Centrifuge API Key')
@click.option('--limit', default=20, help='Number of results to return, use -1 for no limit')
@click.option('--outfmt', default='human', help='Output format of command', type=click.Choice(['human', 'json', 'csv']))
@click.option('--field', '-f', multiple=True, metavar='FIELD', help="Select field(s) when output is human or csv")
@click.option('--ssl-no-verify', help="Disables SSL certificate verification", is_flag=True)
@click.version_option(PACKAGE_VERSION)
@click.pass_context
def cli(ctx, endpoint, apikey, limit, outfmt, field, ssl_no_verify):
    ctx.obj = Cli(endpoint, apikey, limit, outfmt, field, ssl_no_verify)


@cli.group()
@pass_cli
def reports(cli):
    pass


@reports.command(name="list")
@pass_cli
def list_command(cli):
    result = cli.do_GET('/api/upload', query_list=['sorters[0][field]=id',
                                                   'sorters[0][dir]=desc'])
    cli.echo(result)
    return(result)


def get_stats_obj(cli, ctx, include_individuals):
    outfmt = cli.outfmt
    cli.outfmt = 'json'
    cli.echo_enabled = False
    cli.limit = -1

    reports_json = json.loads(ctx.invoke(list_command))
    account_json = json.loads(ctx.invoke(account_info))
    users_json = None
    if account_json['isAdministrator']:
        users_json = json.loads(ctx.invoke(users_list))

    stats_obj = CentrifugeStats(reports_json, users_json, account_json, include_individuals)

    cli.echo_enabled = True
    cli.outfmt = outfmt
    return(stats_obj)


@reports.command(name='stats-summary')
@click.option('--include-individuals', help='Will include statistics for accounts without an Organization', is_flag=True)
@click.pass_context
@pass_cli
def stats_summary(cli, ctx, include_individuals):
    stats_obj = get_stats_obj(cli, ctx, include_individuals)
    result = stats_obj.get_summary(cli.outfmt)
    cli.echo(result)
    return(result)


@reports.command(name='stats-detailed')
@click.option('--include-individuals', help='Will include statistics for accounts without an Organization', is_flag=True)
@click.pass_context
@pass_cli
def stats_detailed(cli, ctx, include_individuals):
    stats_obj = get_stats_obj(cli, ctx, include_individuals)
    result = stats_obj.get_detailed(cli.outfmt, cli.endpoint_scheme, cli.endpoint_netloc)
    cli.echo(result)
    return(result)


@reports.command()
@click.argument('searchterm', required=True)
@pass_cli
def search(cli, searchterm):
    result = cli.do_GET('/api/upload', query_list=['sorters[0][field]=id',
                                                   'sorters[0][dir]=desc',
                                                   'filters[0][field]=search',
                                                   'filters[0][type]=like',
                                                   f'filters[0][value]={searchterm}'])
    cli.echo(result)
    return(result)


@cli.group()
@click.option('--ufid', required=True, metavar='ID', help='Centrifuge report ID')
@pass_cli
def report(cli, ufid):
    cli.ufid = ufid


@report.command()
@pass_cli
def delete(cli):
    result = cli.do_DELETE('/api/upload', query_list=[f'ufid={cli.ufid}', ])
    cli.echo(result)
    return(result)


@report.command()
@pass_cli
def info(cli):
    result = cli.do_GET(f'/api/upload/details/{cli.ufid}')
    cli.echo(result)
    return(result)


@report.command(deprecated=True)
@pass_cli
def crypto(cli):
    """deprecated (use certificates, public-keys, and private-keys)"""
    result = cli.do_GET(f'/api/report/crypto/{cli.ufid}', query_list=['sorters[0][field]=path',
                                                                      'sorters[0][dir]=asc'])
    cli.echo(result)
    return(result)


@report.command()
@pass_cli
def passhash(cli):
    result = cli.do_GET(f'/api/report/passwordhash/{cli.ufid}')
    cli.echo(result)
    return(result)


@report.command()
@pass_cli
def guardian(cli):
    result = cli.do_GET(f'/api/report/{cli.ufid}/analyzer-results', query_list=['affected=true&sorters[0][field]=name',
                                                                                'sorters[0][dir]=asc'])
    cli.echo(result)
    return(result)


@report.command()
@pass_cli
def sbom(cli):
    result = cli.do_GET(f'/api/report/{cli.ufid}/components/pathmatches')
    cli.echo(result)
    return(result)


@report.command(name='code-summary')
@pass_cli
def code_summary(cli):
    result = cli.do_GET(f'/api/report/{cli.ufid}/vulnerable-files',
                        query_list=['sorters[0][field]=id', 'sorters[0][dir]=asc'], paginated=True)
    cli.echo(result)
    return(result)


@report.command(name='code-static')
@click.option('--exid', required=True, metavar='EXID', help='Extraction ID from code-summary output')
@click.option('--path', required=True, metavar='PATH', help='File path that you want to get analysis results for')
@pass_cli
def code_static(cli, exid, path):
    query_list = ['sorters[0][field]=id', 'sorters[0][dir]=asc']
    if exid and path:
        query_list.append(f'path={path}')

    result = cli.do_GET(f'/api/report/{cli.ufid}/vulnerable-files/{exid}', query_list=query_list)
    cli.echo(result)
    return(result)


@report.command(name='code-emulated')
@click.option('--exid', metavar='EXID', default=0, help='Extraction ID from code-summary output')
@click.option('--path', metavar='PATH', default=None, help='File path that you want to get analysis results for')
@pass_cli
def code_emulated(cli, exid, path):
    query_list = ['sorters[0][field]=id', 'sorters[0][dir]=asc']
    if exid and path:
        query_list.append(f'path={path}')

    result = cli.do_GET(f'/api/report/{cli.ufid}/emulated-files/{exid}', query_list=query_list)
    cli.echo(result)
    return(result)


@report.command()
@pass_cli
def certificates(cli):
    result = cli.do_GET(f'/api/report/crypto/{cli.ufid}/certificates', paginated=True)
    cli.echo(result)
    return(result)


@report.command(name='private-keys')
@pass_cli
def private_keys(cli):
    result = cli.do_GET(f'/api/report/crypto/{cli.ufid}/privateKeys', paginated=True)
    cli.echo(result)
    return(result)


@report.command(name='public-keys')
@pass_cli
def public_keys(cli):
    result = cli.do_GET(f'/api/report/crypto/{cli.ufid}/publicKeys', paginated=True)
    cli.echo(result)
    return(result)


@report.command(name='binary-hardening')
@pass_cli
def binary_hardening(cli):
    result = cli.do_GET(f'/api/report/{cli.ufid}/binary-hardening', paginated=True)
    cli.echo(result)
    return(result)


@report.command(name='security-checklist')
@pass_cli
def security_checklist(cli):
    result = cli.do_GET(f'/api/report/SecurityChecklist/{cli.ufid}', paginated=False)
    cli.echo(result)
    return(result)


@report.command(name='check-policy')
@click.option('--policy-yaml', metavar='FILE', type=click.Path(), help='Centrifuge policy yaml file.', required=True)
@click.option('--report-template', metavar='FILE', type=click.Path(), help='Policy report template file.', required=False)
@click.pass_context
@pass_cli
def check_policy(cli, ctx, policy_yaml, report_template):
    outfmt = cli.outfmt
    cli.outfmt = 'json'
    cli.echo_enabled = False
    cli.limit = -1
    certificates_json = json.loads(ctx.invoke(certificates))
    private_keys_json = json.loads(ctx.invoke(private_keys))
    binary_hardening_json = json.loads(ctx.invoke(binary_hardening))
    guardian_json = json.loads(ctx.invoke(guardian))
    code_summary_json = json.loads(ctx.invoke(code_summary))
    passhash_json = json.loads(ctx.invoke(passhash))
    checklist_json = json.loads(ctx.invoke(security_checklist))
    info_json = json.loads(ctx.invoke(info))

    policy_obj = CentrifugePolicyCheck(certificates_json,
                                       private_keys_json,
                                       binary_hardening_json,
                                       guardian_json,
                                       code_summary_json,
                                       passhash_json,
                                       checklist_json,
                                       info_json)

    policy_obj.check_rules(policy_yaml)

    if report_template:
        result = policy_obj.generate_report(report_template)
    elif outfmt == 'json':
        result = policy_obj.generate_json()
    else:
        result = policy_obj.generate_csv()

    cli.echo_enabled = True
    cli.outfmt = outfmt
    cli.echo(result)
    return(result)


@cli.command()
@click.option('--make', metavar='MAKE', help='Manufacturer Name', required=True)
@click.option('--model', metavar='MODEL', help='Model Number', required=True)
@click.option('--version', metavar='VERSION', help='Firmware Version Number', required=True)
@click.option('--chunksize', default=2000000, help='Chunk size in bytes to split the file up into when uploading. Default: 2MB')
@click.argument('filename', type=click.Path(), required=True)
@pass_cli
def upload(cli, make, model, version, chunksize, filename):
    with open(filename, 'rb') as upload_file:
        basename = os.path.basename(filename)
        dzUuid = str(uuid.uuid1())
        chunkIndex = 0
        totalFileSize = os.fstat(upload_file.fileno()).st_size
        totalChunkCount = math.ceil(totalFileSize / chunksize)
        res = None
        for chunkIndex in range(0, totalChunkCount):
            chunkOffset = chunkIndex * chunksize
            upload_file.seek(chunkOffset)
            chunkData = upload_file.read(chunksize)
            files = {
                'file': (basename, chunkData)
            }
            data = {
                'vendor': make,
                'device': model,
                'version': version,
                'dzuuid': dzUuid,
                'dzchunkindex': chunkIndex,
                'dztotalfilesize': totalFileSize,
                'dzchunksize': chunksize,
                'dztotalchunkcount': totalChunkCount,
                'dzchunkbytesoffset': chunkOffset
            }
            res = cli.do_POST('/api/upload/chunky', data, files=files)
        ufid = res.json()['ufid']
        result = f'Upload complete. Report id is {ufid}'
        if cli.outfmt == 'json':
            result = res.text
        elif cli.outfmt == 'csv':
            result = f'id,\n{ufid}\n'

        cli.echo(result)
        return(result)


@cli.group()
@pass_cli
def users(cli):
    pass


@users.command(name="list")
@pass_cli
def users_list(cli):
    result = cli.do_GET('/api/user')
    cli.echo(result)
    return(result)


@users.command()
@click.option('--email', metavar='EMAIL', help='Email address of new user', required=True)
@click.option('--password', metavar='PASSWORD', help='Password for new user, if none supplied it will be auto-generated')
@click.option('--orgid', metavar='ID', help='Organization ID for the new user.', type=int)
@click.option('--admin', help='If set user will have administrative privileges', is_flag=True)
@click.option('--expires', help='Specify a date or time interval. For example "2019-07-04" or "in 2 weeks".')
@click.option('--no-expire', help='If set user will never expire.', is_flag=True)
@pass_cli
def new(cli, email, password, orgid, admin, expires, no_expire):
    if not no_expire and expires is None:
        raise RuntimeError('Must specify expiry date or --no-expire')

    if no_expire:
        isPermanent = True
        expiresAt = "-"
    else:
        isPermanent = False
        dt = dateparser.parse(expires)
        if dt < datetime.now():
            raise RuntimeError('Expiry date is in the past, be sure to use "in" if specifying a time interval i.e. "in 2 weeks"')

        expiresAt = dt.strftime("%Y-%m-%d")
    post_data = {
        'username': email,
        'password': password,
        'organizationId': orgid,
        'isAdmin': admin,
        'isTrial': False,
        'isPermanent': isPermanent,
        'expiresAt': expiresAt}

    result = cli.do_POST('/api/user', post_data)
    cli.echo(result)
    return(result)


@cli.command(name='account-info')
@pass_cli
def account_info(cli):
    result = cli.do_GET(f'/api/user/account')
    cli.echo(result)
    return(result)


@cli.group()
@click.option('--userid', metavar='ID', help='User ID of the user being modified', required=True)
@pass_cli
def user(cli, userid):
    cli.userid = userid


@user.command()
@pass_cli
def delete(cli):
    result = cli.do_DELETE(f'/api/user/{cli.userid}')
    cli.echo(result)
    return(result)


@user.command(name='set-expiration')
@click.argument('expires', metavar='DATE')
@pass_cli
def set_expiration(cli, expires):
    dt = dateparser.parse(expires)
    if dt < datetime.now():
        raise RuntimeError('Expiry date is in the past')

    expiresAt = dt.strftime("%Y-%m-%d")

    put_data = {
        'isPermanent': False,
        'expiresAt': expiresAt}

    result = cli.do_PUT(f'/api/user/{cli.userid}', put_data)
    cli.echo(result)
    return(result)


@user.command(name='set-password')
@click.argument('password', metavar='PASSWORD')
@pass_cli
def set_password(cli, password):
    put_data = {
        'password': password}

    result = cli.do_PUT(f'/api/user/{cli.userid}', put_data)
    cli.echo(result)
    return(result)


@user.command(name='set-organization-id')
@click.argument('orgid', metavar='ID')
@pass_cli
def set_organization_id(cli, orgid):
    put_data = {
        'organizationId': int(orgid)}

    result = cli.do_PUT(f'/api/user/{cli.userid}', put_data)
    cli.echo(result)
    return(result)


@user.command(name='set-email')
@click.argument('email', metavar='EMAIL')
@pass_cli
def set_email(cli, email):
    put_data = {
        'username': email}

    result = cli.do_PUT(f'/api/user/{cli.userid}', put_data)
    cli.echo(result)
    return(result)


@user.command(name='make-permanent')
@pass_cli
def make_permanent(cli):
    put_data = {
        'isPermanent': True,
        'expiresAt': "-"}

    result = cli.do_PUT(f'/api/user/{cli.userid}', put_data)
    cli.echo(result)
    return(result)


@user.command(name='make-admin')
@pass_cli
def make_admin(cli):
    put_data = {
        'isAdmin': True}

    result = cli.do_PUT(f'/api/user/{cli.userid}', put_data)
    cli.echo(result)
    return(result)


@cli.group()
@pass_cli
def orgs(cli):
    pass


@orgs.command(name="list")
@pass_cli
def orgs_list(cli):
    result = cli.do_GET('/api/organization')
    cli.echo(result)
    return(result)


@orgs.command()
@click.option('--ownerid', metavar='ID', help='User id of the owner of this organization', required=True)
@click.argument('name', metavar='ORG_NAME')
@pass_cli
def new(cli, ownerid, name):
    post_data = {
        'ownerId': ownerid,
        'name': name}
    result = cli.do_POST('/api/organization', post_data)
    cli.echo(result)
    return(result)


@cli.group()
@click.option('--orgid', metavar='ID', help='Organization id', required=True)
@pass_cli
def org(cli, orgid):
    cli.orgid = orgid


@org.command()
@click.option('--ownerid', metavar='OWNERID', help='User ID of the owner of this organization', required=True)
@click.option('--name', metavar='NAME', help='Name of this organization', required=True)
@pass_cli
def change(cli, ownerid, name):
    put_data = {
        'name': name,
        'ownerId': int(ownerid)}

    result = cli.do_PUT(f'/api/organization/{cli.orgid}', put_data)
    cli.echo(result)
    return(result)


if __name__ == '__main__':
    cli()
