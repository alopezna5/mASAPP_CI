# -*- coding: utf-8 -*-

import os

from elevenpaths_auth import mASAPP_CI_auth
from tabulate import tabulate
import json


class mASAPP_CI():
    """

    TODO ADD MASAPP_CI INFO
    """

    LANGUAGES = ["en", "es"]

    def __init__(self, key, secret):
        """
        :param key:
        :param secret:
        :var auth_user
        :var scan_info:
        :var scan_result:
        :var exceeded_limit:
        """
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
        """

        :return: It prints the information that is stored in self.exceeded_limit. This printing will vary depending on
                 the type of the values contained in self.exceeded_limit["expected"] and self.exceeded_limit["obtained"].

                * If both elements are dictionaries it would print the elements that surpass the limit that the user\
                has defined.

                    **Example:**

                    .. code-block:: bash

                         ELEMENT                MAX_EXPECTED    OBTAINED
                        ----------------------  --------------  ----------
                        High vulnerabilities         0             1
                        Medium vulnerabilities       0             2
                        Low vulnerabilities          0             5
                        Low behaviorals              0             1

               * If not, it would print the maximum riskscore defined by the user and the obtained riskscore.


        """

        expected = self.exceeded_limit["expected"]
        obtained = self.exceeded_limit["obtained"]

        to_print = [["ELEMENT", "MAX_EXPECTED", "OBTAINED"]]

        if type(obtained) == dict and type(expected) == dict:
            for key in obtained.keys():
                for risk_key, value in obtained[key].items():
                    to_print.append(
                        ['{risk_key} {key}'.format(risk_key=risk_key, key=str(key)).capitalize(),
                         int(expected[key][risk_key]),
                         value
                         ]
                    )

            print(tabulate(to_print, headers='firstrow', stralign='center'))
            print(" ")
        elif type(obtained) != dict and type(expected) != dict:
            to_print.append(['risk', expected, obtained])
            print(tabulate(to_print, headers='firstrow', stralign='center'))
            print(" ")
        else:
            raise TypeError("Error in the expected and obtained values type")

    def _print_details(self, mode, max_values=None):
        """

        :param mode:
        :return:
        """

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


        elif mode == 'standard' and max_values is not None:
            nvulns_to_print = [['Risk category', 'Expected', 'Obtained']]
            nvulns_to_print.append(['Critical', max_values['vulnerabilities']['critical'], v_critical])
            nvulns_to_print.append(['High', max_values['vulnerabilities']['high'], v_high])
            nvulns_to_print.append(['Medium', max_values['vulnerabilities']['medium'], v_medium])
            nvulns_to_print.append(['Low', max_values['vulnerabilities']['low'], v_low])
            print(u'\n\nVulnerabilities')
            print(tabulate(nvulns_to_print, headers='firstrow', stralign='center', tablefmt='simple'))

            nbehav_to_print = [['Risk category', 'Expected', 'Obtained']]
            nbehav_to_print.append(['Critical', max_values['behaviorals']['critical'], b_critical])
            nbehav_to_print.append(['High', max_values['behaviorals']['high'], b_high])
            nbehav_to_print.append(['Medium', max_values['behaviorals']['medium'], b_medium])
            nbehav_to_print.append(['Low', max_values['behaviorals']['low'], b_low])
            print(u'\n\nBehaviors')
            print(tabulate(nbehav_to_print, headers='firstrow', stralign='center', tablefmt='simple'))

    def _lower_than_scan_result(self, element, key, max_expected_value):
        """

        :param element:          The element to check from the scan_result dict
        :type  element:          "vulnerabilities"/"behaviorals"/"behaviors"
        :param key:              The key from scan_result[element][key] for checking the value of the already done scan
        :type  key:              String
        :param expected_value:   The value to compare with scan_result[element][key].
        :type  expected_value:   String
        :return:                 It returns True if the given value max_expected_value is  greater or equal than the
                                 number of vulnerabilities or behaviors (depending on the value of "element") for a
                                 criticality level given by the param "key".


        """
        possible_element_values = ["vulnerabilities", "behaviorals", "behaviors"]
        possible_key_values = ["critical", "high", "medium", "low"]

        if element not in possible_element_values:
            raise ValueError("Element must be 'vulnerabilities', 'behaviorals' or 'behaviors'")

        if key not in possible_key_values:
            raise ValueError("Element must be 'critical', 'high', 'medium', 'low'")

        if element == "behaviors":
            element = "behaviorals"

        if not max_expected_value == "":
            return int(max_expected_value) >= len(self.scan_result[element][key])

        return True

    def _check_not_api_error(self, api_response):
        """

        :param api_response:  An API response that contains the fields "_status" and "_body".
        :type  api_response:  Dictionary
        :return:              Some of the errors from mASAPPs API are shown in the response body, so this method\
                              checks that the status and the body don't contains any error code.
        """

        if api_response is None:
            raise TypeError("ERROR API Response is None")

        if api_response is "":
            raise ValueError("ERROR API Response is empty")

        if api_response == json.loads("{}"):
            raise ValueError("ERROR API Response dict is empty")

        if api_response._status is not None:
            if api_response._status != 200:
                raise ValueError("ERROR in API response: status is {0}".format(api_response._status))

        if api_response._body is not None:
            if 'error' in json.loads(api_response._body):
                raise ValueError("ERROR in API response: body is {0}".format(api_response._body))

        return True

    def store_workgroup(self, wg_number):
        """

        :param wg_number: The position of the workgroup that the user wants to use in the scan.
        :type  wg_number: Integer
        :return:          It returns the workgroup in the position given in wg_number.

        """
        wg = self.auth_user.get_auth_workgroup()
        self._check_not_api_error(wg)
        self.scan_info['wg'] = wg.data['data']['workgroups'][wg_number]['workgroupId']

    def upload_app(self, app_path):
        """

        :param app_path: The absolute path to the application which the user wants to upload.
        :type  app_path: String
        :return:         It makes a check that would throw an error if there is any error in the api response.

        """
        filePath = os.path.abspath(app_path)
        api_response = self.auth_user.post_auth_upload_app(self.scan_info["wg"], "false", filePath)
        self._check_not_api_error(api_response)

    def store_scan_info_from_package_name_origin(self, package_name_origin):
        """

        :param package_name_origin: The packageNameOrigin that mASAPP gives to the app.
        :type  package_name_origin: String
        :return:                    It obtains all the scans from the user with the given credentials and look for the
                                    scan with the same packageNameOrigin than the given as package_name_origin and store
                                    the scanId and scanDate in scan_info. It could throw errors due to: an error in the
                                    API request (/scans) or if there is not any scan with the given packageNameOrigin.

        """

        user_scans = self.auth_user.get_auth_scans(self.scan_info["wg"])
        self._check_not_api_error(user_scans)
        for scan in user_scans.data['data']['scans']:
            if scan['packageNameOrigin'] == package_name_origin:
                self.scan_info['scanId'] = scan['scanId']
                self.scan_info['scanDate'] = scan['lastScanDate']
                return True
        raise ValueError("Application {package_name_origin} not found".format(package_name_origin=package_name_origin))

    def store_scan_info_from_package_name(self, app_path):
        """

        :param app_path: The absolute path to the application which the user wants to upload.
        :type  app_path: String
        :return:         It obtains all the scans from the user with the given credentials and look for the
                         scan whose packageName is contained in the name of the file (app_path).
                         This field is not always generated by mASAPP, so if it is not in the API response it makes the
                         same comparison with the packageNameOrigin.

                            * If it is found, it returns True and store the scanId and scanDate in scan_info.
                            * If it is not found, it throw an error and a list of the different scans of the user for\
                            adding it manually.

        """

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
            "Sometimes mASAPP can not generate all the necessary fields for unequivocally automatic finding of the application, so, please add the packageNameOrigin of your application with the param -p")
        print("You could find your app in the following list:")
        for scan in user_scans.data['data']['scans']:
            print(scan)
            print(" ")

        raise ValueError("Application {app_path} not found".format(app_path=app_path))

    def store_scan_summary_from_scan_id(self, scan_id):
        """

        :param scan_id: The scanId of the scan that the user wants to analyse
        :type  scan_id: String
        :return:        If the scanId is found, it stores the appKey, which is the last necessary field for getting the
                        scan result.

        """

        user_scan_summary = self.auth_user.get_scan_summary(self.scan_info["wg"], scan_id)
        self._check_not_api_error(user_scan_summary)
        for scan_summary in user_scan_summary.data['data']['scanSummaries']:
            if scan_summary['scanDate'] == self.scan_info['scanDate']:
                if len(scan_summary['scannedVersions']) is not 0:
                    self.scan_info['appKey'] = scan_summary['scannedVersions'][0]['appKey']
                    return True
        return False

    def store_scan_result(self):
        """

        :return: It get the scan result and store it in "scan_result". The info that is stored is:

                * riskScore

                * Vulnerabilities

                    * Critical
                    * High
                    * Medium
                    * Low

                * Behaviors

                    * Critical
                    * High
                    * Medium
                    * Low

        """

        if self.scan_info['lang'].lower() not in self.LANGUAGES:
            raise ValueError(
                "Language {language} Only supported languages: en , es".format(language=self.scan_info['lang']))

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
        """

        :param app_path:            The absolute path to the application which the user wants to upload.
        :type  app_path:            String
        :param package_name_origin: The packageNameOrigin that mASAPP gives to the app.
        :type  package_name_origin: String
        :param workgroup:           The position of the workgroup that the user wants to use in the scan.
        :type  workgroup:           Integer
        :param lang:                The language in which the user wants to get the analysis result.
        :type  lang:                "en", "es"
        :return:                    It store the app scan result in "scan_result". The process that it follow is:

                                        1. It store the workgroup in the position given (or the first workgroup by default)
                                        2. Application uploading to mASAPP
                                        3. Storing of the scan info looking for it in the user scans
                                        4. Language setting
                                        5. Scan summary storing
                                        6. Storing the scan result using the info stored in steps 1,3,5 for making a \
                                        request to mASAPP API



        """

        if workgroup == None:
            self.store_workgroup(0)
        else:
            self.store_workgroup(workgroup)

        retries = 0
        scan_found = False

        while retries < 5 and not scan_found:
            retries += 1
            self.upload_app(app_path)

            if package_name_origin != None:
                self.store_scan_info_from_package_name_origin(package_name_origin)

            else:
                self.store_scan_info_from_package_name(app_path)

            self.scan_info['lang'] = lang or 'en'

            if self.store_scan_summary_from_scan_id(self.scan_info['scanId']):
                scan_found = True

        if not scan_found:
            raise ValueError("There is an error  in mASAPP and your application hasn't been successfully processed")
        self.store_scan_result()

    def riskscoring_execution(self, maximum_riskscoring, app_path, package_name_origin=None, workgroup=None, lang=None,
                              detail=None):
        """

        :param maximum_riskscoring: The maximum risk score allowed without throing an error.
        :type  maximum_riskscoring: Float
        :param app_path:            The absolute path to the application which the user wants to upload.
        :type  app_path:            String
        :param package_name_origin: The packageNameOrigin that mASAPP gave to the app. If is the first uploading of the\
                                    app, don't add this parameter.
        :type  package_name_origin: String
        :param workgroup:           The position of the workgroup that the user wants to use in the scan.
        :type  workgroup:           Integer
        :param lang:                The language in which the user wants to get the analysis result.
        :type  lang:                "en", "es"
        :param detail:              If the user wants a detailed execution or not.
        :type  detail:              Boolean
        :return:
                                        * If package_name_origin is sent, it returns an static analysis from the app\
                                        code showing the following information:

                                            * RISKSCORING SUCCESS or RISKSCORING ERROR depending on whether the\
                                             obtained riskscore surpass the maximum given as maximum_riskscoring.

                                                * The standard error includes a table with all the defined limits surpassed

                                            * If detail is equal to True, it will add below two lists:

                                                * A list of vulnerabilities, adding the tittle, risk, number of\
                                                occurrences and the different occurrences with their evidences.

                                                * A list of behaviors, adding the tittle, number of occurrences, impact\
                                                and the different occurrences with their evidences.


                                        * If the package_name_origin is not sent, the script will search in the users\
                                        scans for the correct package_name_origin using the package name.

                                            * If it is correctly found, the app would be analysed

                                            * If not, it would throw an error asking the user for the packageNameOrigin.\
                                            In order to facilitate the user to find the packageNameOrigin it would throw\
                                            a list of all the user scans.

                                            The **packageNameOrigin error text** is exactly: *Sometimes the\
                                            packageNameOrigin is not correctly generated by mASAPP and the application\
                                            is saved without it, so, please add the packageNameOrigin of your\
                                            application with the param -p*


        """
        self.upload_and_analyse_app(app_path=app_path, package_name_origin=package_name_origin, workgroup=workgroup,
                                    lang=lang)

        correct_execution = True

        if self.scan_result['riskScore'] < maximum_riskscoring:
            print("---- RISKSCORING SUCCESS ----\n")
        else:
            self.exceeded_limit["expected"] = maximum_riskscoring
            self.exceeded_limit["obtained"] = self.scan_result['riskScore']
            print("---- RISKSCORING ERROR ----\n")
            self._print_excess()
            correct_execution = False

        if detail == True:
            self._print_details('riskscoring')

        return correct_execution

    def standard_execution(self, scan_maximum_values, app_path, package_name_origin=None, workgroup=None, lang=None,
                           detail=None):
        """

        :param scan_maximum_values: Maximum results allowed without throwing an error.

            **Example**:

             .. code-block:: json

                {
                    "vulnerabilities":
                        {
                            "critical":"maximum of critical vulnerabilities",
                            "high":"maximum of high vulnerabilities",
                            "medium":"maximum of medium vulnerabilities",
                            "low":"maximum of low vulnerabilities"

                        },
                    "behaviorals":
                        {
                            "critical":"maximum of critical behaviors",
                            "high":"maximum of high behaviors",
                            "medium":"maximum of medium behaviors",
                            "low":"maximum of low behaviors"
                        }
                }

        :type  scan_maximum_values: Dictionary
        :param app_path:            The absolute path to the application which the user wants to upload.
        :type  app_path:            String
        :param package_name_origin: The packageNameOrigin that mASAPP gave to the app. If is the first uploading of the\
                                    app, don't add this parameter.
        :type  package_name_origin: String
        :param workgroup:           The position of the workgroup that the user wants to use in the scan.
        :type  workgroup:           Integer
        :param lang:                The language in which the user wants to get the analysis result.
        :type  lang:                "en", "es"
        :param detail:              If the user wants a detailed execution or not.
        :type  detail:              Boolean
        :return:
                                        * If package_name_origin is sent, it returns an static analysis from the app\
                                        code showing the following information:

                                            * STANDARD SUCCESS or STANDARD ERROR depending on whether or not there are\
                                            elements that exceed the limits contained in the scan_maximum_values json.

                                                * The standard error includes a table with all the defined limits surpassed

                                            * If detail is equal to True, it will add below two lists:

                                                * A list of vulnerabilities, adding the tittle, risk, number of\
                                                occurrences and the different occurrences with their evidences
                                                * A list of behaviors, adding the tittle, number of occurrences, impact\
                                                and the different occurrences with their evidences


                                        * If the package_name_origin is not sent, the script will search in the users\
                                        scans for the correct package_name_origin using the package name.

                                            * If it is correctly found, the app would be analysed

                                            * If not, it would throw an error asking the user for the packageNameOrigin.\
                                            In order to facilitate the user to find the packageNameOrigin it would throw\
                                            a list of all the user scans.

                                            The **packageNameOrigin error text** is exactly: *Sometimes mASAPP\
                                            can not generate all the necessary fields for unequivocally automatic \
                                            finding of the application, so, please add the packageNameOrigin of your\
                                            application with the param -p*

        """

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
            self._print_details('standard', max_values=scan_maximum_values)

        return correct_execution
