# -*- coding: utf-8 -*-

import os

from elevenpaths_auth import mASAPP_CI_auth
from tabulate import tabulate
import json


class mASAPP_CI():
    LANGUAGES = ["en", "es"]

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
        expected = self.exceeded_limit["expected"]
        obtained = self.exceeded_limit["obtained"]

        to_print = [["ELEMENT", "EXPECTED", "OBTAINED"]]

        if type(obtained) == dict:
            for key in obtained.keys():
                for risk_key, value in obtained[key].items():
                    to_print.append(
                        ['{risk_key} {key}'.format(risk_key=risk_key, key=str(key)).capitalize(), value,
                         expected[key][risk_key]])

            print(tabulate(to_print, headers='firstrow', stralign='center'))
            print(" ")
        else:
            to_print.append(['risk', expected, obtained])
            print(tabulate(to_print, headers='firstrow', stralign='center'))
            print(" ")

    def __print_details(self, mode):

        v_to_print = [[]]

        for category in self.scan_result['vulnerabilities'].keys():
            for element in self.scan_result['vulnerabilities'][category]:
                v_to_print.append(['Title', element['title']])
                v_to_print.append(['Risk', element['riskLevel']])
                v_to_print.append(['nOcurrences', element['count']])
                v_to_print.append(['Recommendation', element['recommendation']])
                v_to_print.append(['Ocurrences:', ""])

                for occurrence in element['result']:
                    occurrence_path = ""

                    for ocurrence_path_element in occurrence['source'][0]:
                        occurrence_path += ocurrence_path_element + " > "

                    v_to_print.append(['>>>> Source', occurrence_path[:-2]])
                    v_to_print.append(['>>>> Evidence', occurrence['value']])
                    v_to_print.append([' ', ' '])

                v_to_print.append([' ', ' '])
                v_to_print.append([' ', ' '])

        print("VULNERABILITIES DETECTED")
        print(tabulate(v_to_print, stralign='left', tablefmt='plain'))

        b_to_print = [[]]

        for category in self.scan_result['behaviorals'].keys():
            for element in self.scan_result['behaviorals'][category]:
                b_to_print.append(['Title', element['title']])
                b_to_print.append(['Ocurrences', element['count']])
                b_to_print.append(['Impact', element['impact']])

                for occurrence in element['result']:
                    occurrence_path = ""

                    for ocurrence_path_element in occurrence['source'][0]:
                        occurrence_path += ocurrence_path_element + " > "

                    b_to_print.append(['>>>> Source', occurrence_path[:-2]])
                    b_to_print.append(['>>>> Evidence', occurrence['value']])
                    b_to_print.append([' ', ' '])

                b_to_print.append([' ', ' '])
                b_to_print.append([' ', ' '])

        print("BEHAVIORS DETECTED")
        print(tabulate(b_to_print, stralign='left', tablefmt='plain'))

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
            nvulns_to_print = [['Risk category', 'Obtained']]
            nvulns_to_print.append(['Critical', v_critical])
            nvulns_to_print.append(['High', v_high])
            nvulns_to_print.append(['Medium', v_medium])
            nvulns_to_print.append(['Low', v_low])
            print(u'\n\nVulnerabilities')
            print(tabulate(nvulns_to_print, headers='firstrow', stralign='medium', tablefmt='simple'))

            nbehav_to_print = [['Risk category', 'Obtained']]
            nbehav_to_print.append(['Critical', b_critical])
            nbehav_to_print.append(['High', b_high])
            nbehav_to_print.append(['Medium', b_medium])
            nbehav_to_print.append(['Low', b_low])
            print(u'\n\nBehaviors')
            print(tabulate(nbehav_to_print, headers='firstrow', stralign='medium', tablefmt='simple'))


        elif mode == 'standard':
            nvulns_to_print = [['Risk category', 'Expected', 'Obtained']]
            nvulns_to_print.append(['Critical', v_critical])
            nvulns_to_print.append(['High', v_high])
            nvulns_to_print.append(['Medium', v_medium])
            nvulns_to_print.append(['Low', v_low])
            print(u'\n\nVulnerabilities')
            print(tabulate(nvulns_to_print, headers='firstrow', stralign='medium', tablefmt='simple'))

            nbehav_to_print = [['Risk category', 'Expected', 'Obtained']]
            nbehav_to_print.append(['Critical', b_critical])
            nbehav_to_print.append(['High', b_high])
            nbehav_to_print.append(['Medium', b_medium])
            nbehav_to_print.append(['Low', b_low])
            print(u'\n\nBehaviors')
            print(tabulate(nbehav_to_print, headers='firstrow', stralign='medium', tablefmt='simple'))

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

    def store_scan_info_from_package_name(self, app_path):
        user_scans = self.auth_user.get_auth_scans(self.scan_info["wg"])
        self._check_not_api_error(user_scans)
        for scan in user_scans.data['data']['scans']:
            if 'packageName' in scan.keys():
                if scan['packageName'] in app_path or scan['packageNameOrigin'] in app_path:
                    self.scan_info['scanId'] = scan['scanId']
                    self.scan_info['scanDate'] = scan['lastScanDate']
                    return True
            else:
                if scan['packageNameOrigin'] in app_path:
                    self.scan_info['scanId'] = scan['scanId']
                    self.scan_info['scanDate'] = scan['lastScanDate']
                    return True

        print(
            "Sometimes there are error in mASAPP and the application is saved without package name, so, please add the packageNameOrigin of your application with the param -p")
        print("You could find your app in the following list:")
        for scan in user_scans.data['data']['scans']:
            print(scan)
            print(" ")

        assert False, "Application {app_path} not found".format(app_path=app_path)

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

    def upload_and_analyse_app(self, app_path, package_name_origin=None, workgroup=None, lang=None):
        if workgroup == None:
            self.store_workgroup(0)
        else:
            self.store_workgroup(workgroup)

        self.upload_app(app_path)

        if package_name_origin != None:
            self.store_scan_info_from_package_name_origin(package_name_origin)

        else:
            self.store_scan_info_from_package_name(app_path)

        if lang == None:
            self.scan_info['lang'] = 'en'
        else:
            self.scan_info['lang'] = lang

        self.store_scan_summary_from_scan_id(self.scan_info['scanId'])
        self.store_scan_result()

    def riskscoring_execution(self, maximum_riskscoring, app_path, package_name_origin=None, workgroup=None, lang=None,
                              detail=None):
        self.upload_and_analyse_app(app_path=app_path, package_name_origin=package_name_origin, workgroup=workgroup,
                                    lang=lang)

        if self.scan_result['riskScore'] < maximum_riskscoring:
            print("---- RISKSCORING SUCCESS ----\n")
            if detail == True:
                self.__print_details('riskscoring')
            return True
        else:
            self.exceeded_limit["expected"] = maximum_riskscoring
            self.exceeded_limit["obtained"] = self.scan_result['riskScore']
            print("---- RISKSCORING ERROR ----\n")
            self._print_excess()
            if detail == True:
                self.__print_details('riskscoring')
            return False

    def standard_execution(self, scan_maximum_values, app_path, package_name_origin=None, workgroup=None, lang=None,
                           detail=None):
        self.upload_and_analyse_app(app_path=app_path, package_name_origin=package_name_origin, workgroup=workgroup,
                                    lang=lang)

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
            print("---- STANDARD ERROR ----")
            self._print_excess()
        else:
            print("---- STANDARD SUCCESS ----")

        if detail == True:
            self.__print_details(' ')



