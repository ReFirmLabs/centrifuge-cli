#!/usr/bin/env python3

import os
import json
import math
import uuid
import click
import requests
import dateparser
from datetime import datetime
from collections import MutableMapping
from itertools import chain, starmap

import pandas as pd
import numpy as np

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

    def __init__(self, endpoint, apikey, limit, outfmt, fields):
        self.endpoint = endpoint
        self.apikey = apikey
        self.limit = limit
        self.outfmt = outfmt
        self.fields = fields

    def do_GET(self, uri):
        if '?' not in uri:
            uri = uri + '?'

        res = requests.get(f'{self.endpoint}{uri}&limit={self.limit}&authtoken={self.apikey}')
        res.raise_for_status()

        if self.outfmt == 'json':
            return json.dumps(res.json(), indent=2, sort_keys=True)

        results = res.json()
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

    def do_POST(self, uri, data, files=None):
        if '?' not in uri:
            uri = uri + '?'

        res = requests.post(f'{self.endpoint}{uri}&limit={self.limit}&authtoken={self.apikey}', data=data, files=files)
        res.raise_for_status()
        return res

    def do_PUT(self, uri, data):
        if '?' not in uri:
            uri = uri + '?'

        res = requests.put(f'{self.endpoint}{uri}&limit={self.limit}&authtoken={self.apikey}', data=data)
        res.raise_for_status()
        return res

    def do_DELETE(self, uri):
        if '?' not in uri:
            uri = uri + '?'

        res = requests.delete(f'{self.endpoint}{uri}&authtoken={self.apikey}')
        res.raise_for_status()

        if res.status_code not in (200, 204):
            return('Error occurred, could not delete')
        else:
            return('Deleted')


pass_cli = click.make_pass_decorator(Cli)


@click.group()
@click.option('--endpoint', envvar='CENTRIFUGE_URL',
              default='https://centrifuge.refirmlabs.com', metavar='URL', help='Base URL for Centrifuge server')
@click.option('--apikey', envvar='CENTRIFUGE_APIKEY', required=True,
              metavar='KEY', help='Your Centrifuge API Key')
@click.option('--limit', default=20, help='Number of results to return, use -1 for no limit')
@click.option('--outfmt', default='human', help='Output format of command', type=click.Choice(['human', 'json', 'csv']))
@click.option('--field', '-f', multiple=True, metavar='FIELD', help="Select field(s) when output is human or csv")
@click.version_option('0.1')
@click.pass_context
def cli(ctx, endpoint, apikey, limit, outfmt, field):
    ctx.obj = Cli(endpoint, apikey, limit, outfmt, field)


@cli.group()
@pass_cli
def reports(cli):
    pass


@reports.command(name="list")
@pass_cli
def list_command(cli):
    click.echo(cli.do_GET('/api/upload?sorters[0][field]=id&sorters[0][dir]=desc'))


@reports.command()
@click.argument('searchterm', required=True)
@pass_cli
def search(cli, searchterm):
    click.echo(cli.do_GET(f'/api/upload?sorters[0][field]=id&sorters[0][dir]=desc&filters[0][field]=search&filters[0][type]=like&filters[0][value]={searchterm}'))


@cli.group()
@click.option('--ufid', required=True, metavar='ID', help='Centrifuge report ID')
@pass_cli
def report(cli, ufid):
    cli.ufid = ufid


@report.command()
@pass_cli
def delete(cli):
    click.echo(cli.do_DELETE(f'/api/upload?ufid={cli.ufid}'))


@report.command()
@pass_cli
def info(cli):
    click.echo(cli.do_GET(f'/api/upload/details/{cli.ufid}'))


@report.command()
@pass_cli
def crypto(cli):
    click.echo(cli.do_GET(f'/api/report/crypto/{cli.ufid}?sorters[0][field]=path&sorters[0][dir]=asc'))


@report.command()
@pass_cli
def passhash(cli):
    click.echo(cli.do_GET(f'/api/report/passwordhash/{cli.ufid}'))


@report.command()
@pass_cli
def guardian(cli):
    click.echo(cli.do_GET(f'/api/report/{cli.ufid}/analyzer-results?affected=true&sorters[0][field]=name&sorters[0][dir]=asc'))


@report.command()
@pass_cli
def sbom(cli):
    click.echo(cli.do_GET(f'/api/report/{cli.ufid}/components/pathmatches'))


@report.command(name='code-summary')
@pass_cli
def code_summary(cli):
    click.echo(cli.do_GET(f'/api/report/{cli.ufid}/vulnerable-files?sorters[0][field]=totalFlaws&sorters[0][dir]=desc'))


@report.command(name='code-static')
@click.option('--exid', required=True, metavar='EXID', help='Extraction ID from code-summary output')
@click.option('--path', required=True, metavar='PATH', help='File path that you want to get analysis results for')
@pass_cli
def code_static(cli, exid, path):
    click.echo(cli.do_GET(f'/api/report/{cli.ufid}/vulnerable-files/{exid}?path={path}&sorters[0][field]=offset&sorters[0][dir]=asc'))


@report.command(name='code-emulated')
@click.option('--exid', required=True, metavar='EXID', help='Extraction ID from code-summary output')
@click.option('--path', required=True, metavar='PATH', help='File path that you want to get analysis results for')
@pass_cli
def code_emulated(cli, exid, path):
    click.echo(cli.do_GET(f'/api/report/{cli.ufid}/emulated-files/{exid}?path={path}&sorters[0][field]=id&sorters[0][dir]=asc'))


@cli.command()
@click.option('--make', metavar='MAKE', help='Manufacturer Name', required=True)
@click.option('--model', metavar='MODEL', help='Model Number', required=True)
@click.option('--version', metavar='VERSION', help='Firmware Version Number', required=True)
@click.option('--chunksize', default=2000000, help='Chunk size in bytes to split the file up into when uploading. Default: 2MB')
@click.argument('filename', required=True)
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
            res = cli.do_POST('/api/upload/chunky', data, files)
        ufid = res.json()['ufid']
        click.echo(f"Upload complete. When report is complete you may view results at {cli.endpoint}/report/{ufid}")


@cli.group()
@pass_cli
def users(cli):
    pass


@users.command(name="list")
@pass_cli
def user_list(cli):
    click.echo(cli.do_GET('/api/user'))


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

    click.echo(cli.do_POST('/api/user', post_data))


@cli.group()
@click.option('--userid', metavar='ID', help='User ID of the user being modified', required=True)
@pass_cli
def user(cli, userid):
    cli.userid = userid


@user.command()
@pass_cli
def delete(cli):
    click.echo(cli.do_DELETE(f'/api/user/{cli.userid}'))


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

    click.echo(cli.do_PUT(f'/api/user/{cli.userid}', put_data))


@user.command(name='set-password')
@click.argument('password', metavar='PASSWORD')
@pass_cli
def set_password(cli, password):
    put_data = {
        'password': password}

    click.echo(cli.do_PUT(f'/api/user/{cli.userid}', put_data))


@user.command(name='set-organization-id')
@click.argument('orgid', metavar='ID')
@pass_cli
def set_organization_id(cli, orgid):
    put_data = {
        'organizationId': int(orgid)}

    click.echo(cli.do_PUT(f'/api/user/{cli.userid}', put_data))


@user.command(name='set-email')
@click.argument('email', metavar='EMAIL')
@pass_cli
def set_email(cli, email):
    put_data = {
        'username': email}

    click.echo(cli.do_PUT(f'/api/user/{cli.userid}', put_data))


@user.command(name='make-permanent')
@pass_cli
def make_permanent(cli):
    put_data = {
        'isPermanent': True,
        'expiresAt': "-"}

    click.echo(cli.do_PUT(f'/api/user/{cli.userid}', put_data))


@user.command(name='make-admin')
@pass_cli
def make_admin(cli):
    put_data = {
        'isAdmin': True}

    click.echo(cli.do_PUT(f'/api/user/{cli.userid}', put_data))


@cli.group()
@pass_cli
def orgs(cli):
    pass


@orgs.command(name="list")
@pass_cli
def orgs_list(cli):
    click.echo(cli.do_GET('/api/organization'))


@orgs.command()
@click.option('--ownerid', metavar='ID', help='User id of the owner of this organization', required=True)
@click.argument('name', metavar='ORG_NAME')
@pass_cli
def new(cli, ownerid, name):
    post_data = {
        'ownerId': ownerid,
        'name': name}
    click.echo(cli.do_POST('/api/organization', post_data))


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

    click.echo(cli.do_PUT(f'/api/organization/{cli.orgid}', put_data))


if __name__ == '__main__':
    cli()
