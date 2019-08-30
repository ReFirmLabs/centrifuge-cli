#!/usr/bin/env python3

import os
import json
import math
import uuid
import click
import requests
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
        res = requests.get(f'{self.endpoint}{uri}&limit={self.limit}&authtoken={self.apikey}')
        res.raise_for_status( )

        if self.outfmt == 'json':
            return json.dumps(res.json( ), indent=2, sort_keys=True)
        
        results = res.json( )
        if 'results' in results:
            results = results['results']
        elif not isinstance(results, list):
            results = [results, ]
        flattened = [ ]
        for r in results:
            flattened.append(flatten(r))

        df = pd.read_json(json.dumps(flattened))
        if len(self.fields) > 0 and len(df) > 0:
            df = df[list(self.fields)]

        if self.outfmt == 'csv':
            return df.to_csv( )
        
        return df

    def do_POST(self, uri, data, files=None):
        res = requests.post(f'{self.endpoint}{uri}&limit={self.limit}&authtoken={self.apikey}', data=data, files=files)
        res.raise_for_status( )
        return res

    def do_DELETE(self, uri):
        res = requests.delete(f'{self.endpoint}{uri}&authtoken={self.apikey}')
        res.raise_for_status( )

        if res.status_code is not 204:
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
    cli.ufid=ufid

@report.command()
@pass_cli
def delete(cli):
    click.echo(cli.do_DELETE(f'/api/upload?ufid={cli.ufid}'))

@report.command()
@pass_cli
def info(cli):
    click.echo(cli.do_GET(f'/api/upload/details/{cli.ufid}?'))

@report.command()
@pass_cli
def crypto(cli):
    click.echo(cli.do_GET(f'/api/report/crypto/{cli.ufid}?sorters[0][field]=path&sorters[0][dir]=asc'))

@report.command()
@pass_cli
def passhash(cli):
    click.echo(cli.do_GET(f'/api/report/passwordhash/{cli.ufid}?'))

@report.command()
@pass_cli
def guardian(cli):
    click.echo(cli.do_GET(f'/api/report/{cli.ufid}/analyzer-results?affected=true&sorters[0][field]=name&sorters[0][dir]=asc'))

@report.command()
@pass_cli
def sbom(cli):
    click.echo(cli.do_GET(f'/api/report/{cli.ufid}/components/pathmatches?'))

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
        totalChunkCount = math.ceil(totalFileSize/chunksize)
        res = None
        for chunkIndex in range(0, totalChunkCount):
            chunkOffset = chunkIndex * chunksize;
            upload_file.seek(chunkOffset)
            chunkData = upload_file.read(chunksize);
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
            res = cli.do_POST('/api/upload/chunky?', data, files)
            #response = requests.post('{}:{}/api/upload/chunky?authtoken={}'.format(server, port, api_key), data=data, files=files, verify=False)

        ufid = res.json( )['ufid']
        click.echo(f"Upload complete. When report is complete you may view results at {cli.endpoint}/report/{ufid}")


if __name__ == '__main__':
    cli( )

