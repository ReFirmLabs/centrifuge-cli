#!/usr/bin/env python3

import os
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

    def build_url(self, path, query_list):
        default_query = [f'limit={self.limit}',
                         f'authtoken={self.apikey}']
        if query_list is not None:
            default_query.extend(query_list)

        query = '&'.join(default_query)
        return urlunparse((self.endpoint_scheme, self.endpoint_netloc, path, None, query, None))

    def do_GET(self, path, query_list=None, get_all=False):

        # handle paginated queries
        if get_all:
            results = []
            total = 0
            page = 1
            base_query_list = query_list if query_list else []
            while True:
                updated_query_list = base_query_list + [f'page={page}']
                url = self.build_url(path, updated_query_list)
                try:
                    res = requests.get(url, verify=self.ssl_verify)
                except requests.exceptions.ConnectionError as ex:
                    return f'{{statusCode: 502, message: Could not connect to host: {self.endpoint_netloc}}}'
                if res.status_code != 200:
                    if res.status_code == 403:
                        return "{statusCode: 403, message: User not authorized}"
                    return res.text

                data = res.json()
                # handle binary hardness specifically while that API endpoint is not compliant with the rest
                data = data['checkSecs'] if 'checkSecs' in data else data
                results.extend(data['results'])
                count = data['count']
                total += self.limit
                page += 1

                if total >= count:
                    break

            return json.dumps({'count': count, 'results': results}, indent=2, sort_keys=True)

        else:
            url = self.build_url(path, query_list)
            try:
                res = requests.get(url, verify=self.ssl_verify)
            except requests.exceptions.ConnectionError as ex:
                return f'{{statusCode: 502, message: Could not connect to host: {self.endpoint_netloc}}}'
            if res.status_code != 200:
                if res.status_code == 403:
                    return "{statusCode: 403, message: User not authorized}"
                return res.text
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
        url = self.build_url(path, query_list)
        try:
            res = requests.post(url, data=data, files=files)
        except requests.exceptions.ConnectionError as ex:
            return f'{{statusCode: 502, message: Could not connect to host: {self.endpoint_netloc}}}'
        if res.status_code != 200:
            if res.status_code == 403:
                return "{statusCode: 403, message: User not authorized}"
            return res.text
        return res

    def do_PUT(self, path, data, query_list=None):
        url = self.build_url(path, query_list)
        try:
            res = requests.put(url, data=data)
        except requests.exceptions.ConnectionError as ex:
            return f'{{statusCode: 502, message: Could not connect to host: {self.endpoint_netloc}}}'
        if res.status_code != 200:
            if res.status_code == 403:
                return "{statusCode: 403, message: User not authorized}"
            return res.text
        return res

    def do_DELETE(self, path, query_list=None):
        url = self.build_url(path, query_list)
        try:
            res = requests.delete(url)
        except requests.exceptions.ConnectionError as ex:
            return f'{{statusCode: 502, message: Could not connect to host: {self.endpoint_netloc}}}'
        if res.status_code != 200:
            if res.status_code == 403:
                return "{statusCode: 403, message: User not authorized}"
            return ('Error occurred, could not delete')

        return('Deleted')

    def echo(self, message):
        if self.echo_enabled:
            click.echo(message)


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


@report.command()
@pass_cli
def crypto(cli):
    click.echo('crypto is a deprecated endpoint and will be removed in future releases, please migrate to certificates and privatekeys',
               err=True)
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
    cli.limit = 100
    result = cli.do_GET(f'/api/report/{cli.ufid}/vulnerable-files', get_all=True,
                        query_list=['sorters[0][field]=id', 'sorters[0][dir]=asc'])
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
    result = cli.do_GET(f'/api/report/crypto/{cli.ufid}/certificates', get_all=True)
    cli.echo(result)
    return(result)


@report.command(name='private-keys')
@pass_cli
def private_keys(cli):
    result = cli.do_GET(f'/api/report/crypto/{cli.ufid}/privateKeys', get_all=True)
    cli.echo(result)
    return(result)


@report.command(name='public-keys')
@pass_cli
def public_keys(cli):
    result = cli.do_GET(f'/api/report/crypto/{cli.ufid}/publicKeys', get_all=True)
    cli.echo(result)
    return(result)


@report.command(name='binary-hardening')
@pass_cli
def binary_hardening(cli):
    result = cli.do_GET(f'/api/report/{cli.ufid}/binary-hardening', get_all=True)
    cli.echo(result)
    return(result)


@report.command(name='check-policy')
@click.option('--policy-yaml', metavar='FILE', type=click.Path(), help='Centrifuge policy yaml file.', required=True)
@click.pass_context
@pass_cli
def check_policy(cli, ctx, policy_yaml):
    outfmt = cli.outfmt
    cli.outfmt = 'json'
    cli.echo_enabled = False
    cli.limit = 1000
    certificates_json = json.loads(ctx.invoke(certificates))
    private_keys_json = json.loads(ctx.invoke(private_keys))
    binary_hardening_json = json.loads(ctx.invoke(binary_hardening))
    guardian_json = json.loads(ctx.invoke(guardian))
    code_summary_json = json.loads(ctx.invoke(code_summary))
    passhash_json = json.loads(ctx.invoke(passhash))

    policy_obj = CentrifugePolicyCheck(certificates_json,
                                       private_keys_json,
                                       binary_hardening_json,
                                       guardian_json,
                                       code_summary_json,
                                       passhash_json)

    policy_obj.check_rules(policy_yaml)

    result = policy_obj.generate_csv()
    if outfmt == 'json':
        result = policy_obj.generate_json()

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
def user_list(cli):
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
