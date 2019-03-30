#!/usr/bin/python
# -*- coding: utf-8 -*-

import os

from elevenpaths_auth import mASAPP_CI_auth


# import logging
# import sys


# Logs for helping the development
# Logs printing
# root = logging.getLogger()
# root.setLevel(logging.DEBUG)
#
# handler = logging.StreamHandler(sys.stdout)
# handler.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# handler.setFormatter(formatter)
# root.addHandler(handler)


class mASAPP_CI():
    LANGUAGES = ["en", "es"]

    RISKLEVELS_EN = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low'}
    RISKLEVELS_ES = {'crítico': 'critical', 'alto': 'high', 'medio': 'medium', 'bajo': 'low'}

    def __init__(self, key, secret):
        self.key = key
        self.secret = secret
        self.auth_user = mASAPP_CI_auth(self.key, self.secret)
        self.scan_info = {
            'wg': None,
            'scanId': None,
            'appKey': None,
            'scanDate': None,
            'lang': None
        }

        self.scan_result = {
            'riskScore': None,
            'behaviorals': {'critical': None, 'high': None, 'medium': None, 'low': None},
            'vulnerabilities': {'critical': None, 'high': None, 'medium': None, 'low': None}
        }

    def store_workgroup(self, wg_number):
        self.scan_info['wg'] = self.auth_user.get_auth_workgroup().data['data']['workgroups'][wg_number]['workgroupId']

    def upload_app(self, app_path):
        filePath = os.path.abspath(app_path)
        self.auth_user.post_auth_upload_app(self.scan_info["wg"], "false", filePath)

    def store_scan_info_from_package_name_origin(self, package_name_origin):
        for scan in self.auth_user.get_auth_scans(self.scan_info["wg"]).data['data']['scans']:
            if scan['packageNameOrigin'] == package_name_origin:
                self.scan_info['scanId'] = scan['scanId']
                self.scan_info['scanDate'] = scan['lastScanDate']
                return True
        assert False, "Application {package_name_origin} not found".format(package_name_origin=package_name_origin)

    def store_scan_summary_from_scan_id(self, scan_id):
        for scan_summary in self.auth_user.get_scan_summary(self.scan_info["wg"], scan_id).data['data'][
            'scanSummaries']:
            if scan_summary['scanDate'] == self.scan_info['scanDate']:
                self.scan_info['appKey'] = scan_summary['scannedVersions'][0]['appKey']
                return True
        assert False, "Scan {scan_id} not found".format(scan_id=scan_id)

    def store_scan_result(self, lang):
        assert lang.lower() in self.LANGUAGES, "Language {language} Only supported languages: en , es".format(
            language=lang)

        scan_result = self.auth_user.get_scan_result(self.scan_info['wg'], self.scan_info['scanId'],
                                                     self.scan_info['scanDate'], self.scan_info['appKey'], lang)

        self.scan_result['riskScore'] = scan_result.data['data']['riskScore']

        for vulnerability in scan_result.data['data']['vulnerabilities']:
            risk = vulnerability['riskLevel'].lower()
            self.scan_result['vulnerabilities'][risk] = vulnerability

        for behavioral in scan_result.data['data']['behaviorals']:
            risk = behavioral['riskLevel'].lower()
            self.scan_result['behaviorals'][risk] = behavioral


if __name__ == '__main__':
    user = mASAPP_CI(key="", secret="")
    user.store_workgroup(0)
    user.upload_app("internal_resources/com.andreea.android.dev.triplelayer1GooglePlay.apk")
    user.store_scan_info_from_package_name_origin("com.andreea.android.dev.triplelayerGooglePlay")
    user.store_scan_summary_from_scan_id(user.scan_info['scanId'])
    user.store_scan_result("es")
    print("Hello this is a main for develop the script!")
