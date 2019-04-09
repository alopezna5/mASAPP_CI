#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import os

from elevenpaths_auth import mASAPP_CI_auth
import argparse

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

ASCII_ART_DESCRIPTION = U'''
                        _____           _____   _____      _____  _____ 
                /\     / ____|   /\    |  __ \ |  __ \    / ____||_   _|
  _ __ ___     /  \   | (___    /  \   | |__) || |__) |  | |       | |  
 | '_ ` _ \   / /\ \   \___ \  / /\ \  |  ___/ |  ___/   | |       | |  
 | | | | | | / ____ \  ____) |/ ____ \ | |     | |       | |____  _| |_ 
 |_| |_| |_|/_/    \_\|_____//_/    \_\|_|     |_|        \_____||_____|
                                                      
'''


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
            'behaviorals': {'critical': [], 'high': [], 'medium': [], 'low': []},
            'vulnerabilities': {'critical': [], 'high': [], 'medium': [], 'low': []}
        }

        self.exceeded_limit = {
            "expected": None,
            "obtained": None
        }

    def _print_excess(self):
        print("Expected: {}".format(self.exceeded_limit["expected"]))
        print("Obtained: {}".format(self.exceeded_limit["obtained"]))

    def __print_details(self, mode):
        vulnerabilities = self.scan_result['vulnerabilities']
        v_critical = len(vulnerabilities['critical'])
        v_high = len(vulnerabilities['high'])
        v_medium = len(vulnerabilities['medium'])
        v_low = len(vulnerabilities['low'])

        behaviorals = self.scan_result['behaviorals']
        b_critical = len(behaviorals['critical'])
        b_high = len(behaviorals['high'])
        b_medium = len(behaviorals['medium'])
        b_low = len(behaviorals['low'])

        if mode == 'riskscoring':
            print(u'Vulnerabilities')
            print(u'''
                            Obtained
                            ────────

            Critical          {n_vul_c}
            High              {n_vul_h}
            Medium            {n_vul_m}
            Low               {n_vul_l}

            '''.format(n_vul_c=v_critical, n_vul_h=v_high, n_vul_m=v_medium, n_vul_l=v_low))
            print(u'Behaviorals')
            print(u'''
                            Obtained 
                            ────────

            Critical            {n_bhv_c}          
            High                {n_bhv_h}          
            Medium              {n_bhv_m}          
            Low                 {n_bhv_l}          

            '''.format(n_bhv_c=b_critical, n_bhv_h=b_high, n_bhv_m=b_medium, n_bhv_l=b_low))

    def _lower_than_scan_result(self, element, key, value):
        if not value == "":
            return len(self.scan_result[element][key]) > int(value)

        else:
            return True

    def _check_not_api_error(self, api_response):
        assert api_response._status == 200, "ERROR Api response is {0}".format(api_response._body)
        assert not 'error' in json.loads(api_response._body), "ERROR Api response is {0}".format(api_response._body)

    def store_workgroup(self, wg_number):
        wg = self.auth_user.get_auth_workgroup()
        self._check_not_api_error(wg)
        self.scan_info['wg'] = wg.data['data']['workgroups'][wg_number]['workgroupId']

    def upload_app(self, app_path):
        filePath = os.path.abspath(app_path)
        api_response = self.auth_user.post_auth_upload_app(self.scan_info["wg"], "false", filePath)
        self._check_not_api_error(api_response)

    def store_scan_info_from_package_name_origin(self, package_name_origin):
        user_scans = self.auth_user.get_auth_scans(self.scan_info["wg"])
        self._check_not_api_error(user_scans)
        for scan in user_scans.data['data']['scans']:
            if scan['packageNameOrigin'] == package_name_origin:
                self.scan_info['scanId'] = scan['scanId']
                self.scan_info['scanDate'] = scan['lastScanDate']
                return True
        assert False, "Application {package_name_origin} not found".format(package_name_origin=package_name_origin)

    def store_scan_summary_from_scan_id(self, scan_id):
        user_scan_summary = self.auth_user.get_scan_summary(self.scan_info["wg"], scan_id)
        self._check_not_api_error(user_scan_summary)
        for scan_summary in user_scan_summary.data['data'][
            'scanSummaries']:
            if scan_summary['scanDate'] == self.scan_info['scanDate']:
                self.scan_info['appKey'] = scan_summary['scannedVersions'][0]['appKey']
                return True
        assert False, "Scan {scan_id} not found".format(scan_id=scan_id)

    def store_scan_result(self):
        assert self.scan_info[
                   'lang'].lower() in self.LANGUAGES, "Language {language} Only supported languages: en , es".format(
            language=self.scan_info['lang'])

        scan_result = self.auth_user.get_scan_result(self.scan_info['wg'], self.scan_info['scanId'],
                                                     self.scan_info['scanDate'], self.scan_info['appKey'],
                                                     self.scan_info['lang'])

        self._check_not_api_error(scan_result)

        self.scan_result['riskScore'] = scan_result.data['data']['riskScore']

        for vulnerability in scan_result.data['data']['vulnerabilities']:
            risk = vulnerability['riskLevel'].lower()
            self.scan_result['vulnerabilities'][risk].append(vulnerability)

        for behavioral in scan_result.data['data']['behaviorals']:
            risk = behavioral['riskLevel'].lower()
            self.scan_result['behaviorals'][risk].append(behavioral)

    def upload_and_analyse_app(self, app_path, package_name_origin, workgroup=None, lang=None):
        if workgroup == None:
            self.store_workgroup(0)
        else:
            self.store_workgroup(workgroup)

        self.upload_app(app_path)
        self.store_scan_info_from_package_name_origin(package_name_origin)
        self.store_scan_summary_from_scan_id(self.scan_info['scanId'])

        if lang == None:
            self.scan_info['lang'] = 'en'
        else:
            self.scan_info['lang'] = lang

        self.store_scan_result()

    def riskscoring_execution(self, maximum_riskscoring, app_path, package_name_origin, workgroup=None, lang=None,
                              detail=None):
        self.upload_and_analyse_app(app_path, package_name_origin, workgroup, lang)

        if self.scan_result['riskScore'] < maximum_riskscoring:
            print("---- RISKSCORING SUCCESS ----")
            if detail == True:
                self.__print_details('riskscoring')
            return True
        else:
            self.exceeded_limit["expected"] = maximum_riskscoring
            self.exceeded_limit["obtained"] = self.scan_result['riskScore']
            print("---- RISKSCORING ERROR ----")
            self._print_excess()
            if detail == True:
                self.__print_details('riskscoring')
            return False

    def standard_execution(self, scan_maximum_values, app_path, package_name_origin, workgroup=None, lang=None,
                           detail=None):
        self.upload_and_analyse_app(app_path, package_name_origin, workgroup, lang)

        self.exceeded_limit["expected"] = {"vulnerabilities": {}, "behaviorals": {}}
        self.exceeded_limit["obtained"] = {"vulnerabilities": {}, "behaviorals": {}}
        correct_execution = True

        for key, value in scan_maximum_values['vulnerabilities'].items():
            if not self._lower_than_scan_result('vulnerabilities', key, value):
                self.exceeded_limit["expected"]['vulnerabilities'][key] = value
                self.exceeded_limit["obtained"]['vulnerabilities'][key] = len(self.scan_result['vulnerabilities'][key])
                correct_execution = False

        for key, value in scan_maximum_values['behaviorals'].items():
            if not self._lower_than_scan_result('behaviorals', key, value):
                self.exceeded_limit["expected"]['behaviorals'][key] = value
                self.exceeded_limit["obtained"]['behaviorals'][key] = len(self.scan_result['behaviorals'][key])
                correct_execution = False

        if not correct_execution:
            print("----  ERROR ----")
            self._print_excess()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='masapp', description=ASCII_ART_DESCRIPTION,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-r', '--riskscore', help='riskscoring execution', type=float, metavar="N")
    parser.add_argument('-d', '--detailed', help='add details to the execution', action='store_true')
    parser.add_argument('-s', '--standard', help='standard execution', action='store_true')
    parser.add_argument('-v', '--values', help='vulnerabilities and behaviorals json', metavar=".json")

    args = parser.parse_args()

    if args.detailed:
        details = True
    else:
        details = False

    if args.riskscore:
        user = mASAPP_CI(key="", secret="")
        user.riskscoring_execution(args.riskscore,
                                   "internal_resources/com.andreea.android.dev.triplelayer1GooglePlay.apk",
                                   "com.andreea.android.dev.triplelayerGooglePlay", detail=details)

    else:
        def check_json(input_json):
            if ".json" in input_json:
                try:
                    input_json = json.load(open(input_json))
                except:
                    parser.print_help()
                    return False
                correct_json = input_json['vulnerabilities'] != None or input_json['behaviorals']

                if not correct_json:
                    parser.print_help()
                    return False
                else:
                    return input_json
            else:
                parser.print_help()
                return False


        if args.standard:
            if not args.values:
                print("missing parameter -v")
            else:
                checked_json = check_json(args.values)
                if checked_json:
                    user = mASAPP_CI(key="", secret="")
                    user.standard_execution(checked_json,
                                            "internal_resources/com.andreea.android.dev.triplelayer1GooglePlay.apk",
                                            "com.andreea.android.dev.triplelayerGooglePlay", detail=True)

                    print(checked_json)
                else:
                    print(
                        u"""
                            -v --values json structure:
                                {
                                  "vulnerabilities": {
                                    "critical": "maximum of critical vulnerabilities",
                                    "high": "maximum of high vulnerabilities",
                                    "medium": "maximum of medium vulnerabilities",
                                    "low": "maximum of low vulnerabilities"
                                  },
                                  "behaviorals": {
                                    "critical": "maximum of critical behaviorals",
                                    "high": "maximum of high behaviorals",
                                    "medium": "maximum of medium behaviorals",
                                    "low": "maximum of low behaviorals"
                                  }
                                }     
                        """
                    )


        else:
            parser.print_help()

    user = mASAPP_CI(key="", secret="")
    # user.riskscoring_execution(8,
    #                            "internal_resources/com.andreea.android.dev.triplelayer1GooglePlay.apk",
    #                            "com.andreea.android.dev.triplelayerGooglePlay", detail=True)

    user.standard_execution(json.load(open("internal_resources/scan-values.json")),
                            "internal_resources/com.andreea.android.dev.triplelayer1GooglePlay.apk",
                            "com.andreea.android.dev.triplelayerGooglePlay", detail=True)
