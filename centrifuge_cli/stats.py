#!/usr/bin/env python3

import json
import dateparser
import pandas as pd
from urllib.parse import urlparse, urlunparse


class CentrifugeStats(object):

    def __init__(self, reports_json, users_json):
        self.reports_json = reports_json
        self.users_json = users_json

        self.user_id_to_org_name = {}
        for user in self.users_json:
            org = user['organization']
            if org is not None:
                self.user_id_to_org_name[user['id']] = org

    def get_summary(self, outfmt):
        org_name_to_upload_md5 = {}

        for report in self.reports_json['results']:
            user_id = report['User']['id']
            if user_id in self.user_id_to_org_name:
                org = self.user_id_to_org_name[user_id]
                if org not in org_name_to_upload_md5:
                    org_name_to_upload_md5[org] = set()
                org_name_to_upload_md5[org].add(report['md5sum'])

        data = []
        for org in set(self.user_id_to_org_name.values()):
            count = 0
            if org in org_name_to_upload_md5:
                count = len(org_name_to_upload_md5[org])

            data.append([org, count])

        df = pd.DataFrame(data, columns=['Organization', 'Unique Uploads'])

        if outfmt == 'csv':
            return(df.to_csv())
        elif outfmt == 'json':
            return(df.to_json(orient='records'))

        return(df)

    def get_detailed(self, outfmt, endpoint_scheme, endpoint_netloc):
        data = []

        for report in self.reports_json['results']:
            user_id = report['User']['id']
            if user_id in self.user_id_to_org_name:
                date = dateparser.parse(report['createdAt'])
                report_url = urlunparse((endpoint_scheme, endpoint_netloc, f"/report/{report['id']}", None, None, None))
                org = self.user_id_to_org_name[user_id]
                vendor = report['vendor']
                model = report['device']
                version = report['version']
                filename = report['originalFilename']
                md5sum = report['md5sum']

                data.append([date, report_url, org, vendor, model, version, filename, md5sum])

        df = pd.DataFrame(data, columns=['Upload Date', 'Report URL', 'Organization', 'Vendor', 'Model', 'Version', 'Filename', 'md5sum'])

        df.sort_values(by='Upload Date', ascending=False, inplace=True)

        if outfmt == 'csv':
            return(df.to_csv())
        elif outfmt == 'json':
            return(df.to_json(orient='records'))

        return(df)
