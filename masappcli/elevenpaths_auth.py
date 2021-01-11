# -*- coding: utf-8 -*-

from sdklib.http import HttpSdk
from sdklib.http.authorization import X11PathsAuthentication
import urllib3


class mASAPP_CI_auth(HttpSdk):
    """

    This class contains the necessary authorized methods for working with the mASAPPs API. Inherited from the
    **HttpSdk** class it uses the **X11PathsAuthentication** authentication which performs safer requests.
    Without this request implementation the user wouldn't be available to communicate with the mASAPPs API.

    The initialization of this class needs two parameters obtained from mASAPP in the API Clients section.
    This parameters are:

    +------------------------+-----------------------+
    | mASAPP_CI_auth param   |Equivalent mASAPP value|
    +========================+=======================+
    | key                    | Client ID             |
    +------------------------+-----------------------+
    | secret                 | Secret                |
    +------------------------+-----------------------+

    For more information about HttpSdk: https://github.com/ivanprjcts/sdklib
    """

    API_VERSION = "2.0.1"
    DEFAULT_HOST = "https://masapp.elevenpaths.com"
    API_WORKGROUPS = "/api/{api_version}/workgroups".format(api_version=API_VERSION)
    API_UPLOAD = "/api/{api_version}/upload".format(api_version=API_VERSION)
    API_SCANS = "/api/{api_version}/scans".format(api_version=API_VERSION)
    API_SCAN_SUMMARY = "/api/{api_version}/scanSummary".format(api_version=API_VERSION)
    API_SCAN_RESULT = "/api/{api_version}/scanResults".format(api_version=API_VERSION)

    def __init__(self, key, secret):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # hide ugly https warnings

        self.authentication_instances = X11PathsAuthentication(key, secret)
        super(mASAPP_CI_auth, self).__init__()

    def get_auth_workgroup(self):
        """

        :return:          The response to the authenticated request **/workgroups**
                          to the mASAPP API, which returns the mASAPPs workgroups which the user belongs to.
        """
        return self.get(url_path=self.API_WORKGROUPS, authentication_instances=[self.authentication_instances])

    def post_auth_upload_app(self, allowTacyt, app_path, workgroup=None):
        """

        :param allowTacyt: If the user wants to share the app with the Tacyt/mASAPP community or not.
        :type allowTacyt:  Boolean
        :param app_path:   The absolute path to the application which the user wants to upload.
        :type app_path:    String
        :param workgroup:  The workgroup where the user belongs to. (Not mandatory) (Not mandatory)
        :type workgroup:   String
        :return:           The response to the authenticated request **/upload**
                           to the mASAPP API, which returns the result of the uploading the app to mASAPP.
        """

        body_params = {
            "allowTacyt": allowTacyt
        }

        if workgroup is None:
            return self.post(url_path=self.API_UPLOAD, authentication_instances=[self.authentication_instances],
                             body_params=body_params, files={'file': app_path})
        else:
            return self.post(url_path=self.API_UPLOAD, authentication_instances=[self.authentication_instances],
                             headers={'wg': workgroup}, body_params=body_params, files={'file': app_path})

    def get_auth_scans(self, workgroup=None):
        """

        :param workgroup:  The workgroup where the user belongs to. (Not mandatory)
        :type workgroup:   String
        :return:           The response to the authenticated request **/scans**
                           to the mASAPP API, which returns a brief summary of all the apps contained in the user scans.
        """
        if workgroup is None:
            return self.get(url_path=self.API_SCANS, authentication_instances=[self.authentication_instances])
        else:
            return self.get(url_path=self.API_SCANS, authentication_instances=[self.authentication_instances],
                            headers={'wg': workgroup})

    def get_auth_scan_by_hashPath(self, hashPath, workgroup=None):
        """

        :param hashPath:   The sha1 of the application whose scan the user wants to get
        :param workgroup:  The workgroup where the user belongs to. (Not mandatory)
        :type workgroup:   String
        :return:           The associated scan to the given hashPath.
        """

        query_params = {
            "hashPath": hashPath
        }

        if workgroup is None:
            return self.get(url_path=self.API_SCANS, authentication_instances=[self.authentication_instances],
                            headers={"Accept": "application/json"}, query_params=query_params)

        else:
            return self.get(url_path=self.API_SCANS, authentication_instances=[self.authentication_instances],
                            headers={'wg': workgroup, "Accept": "application/json"}, query_params=query_params)

    def get_scan_summary(self, scan_id, workgroup=None):
        """
        :param scan_id:    The scan ID from the scan which the user wants to obtain a summary.
        :type scan_id:     String
        :param workgroup:  The workgroup where the user belongs to. (Not mandatory)
        :type workgroup:   String
        :return:           The response to the authenticated request **/scanSummary**
                           to the mASAPP API, which returns a summary of the scan with the scan_id introduced.
        """
        query_params = {
            "pageSize": 50,
            "scanId": scan_id
        }

        if workgroup is None:
            return self.get(url_path=self.API_SCAN_SUMMARY,
                            authentication_instances=[self.authentication_instances], query_params=query_params)
        else:
            return self.get(url_path=self.API_SCAN_SUMMARY,
                            authentication_instances=[self.authentication_instances],
                            headers={'wg': workgroup}, query_params=query_params)

    def get_scan_result(self, scan_id, scan_date, app_key, lang, workgroup=None):
        """

        :param scan_id:   The scan ID from the scan which the user wants to obtain the result.
        :type scan_id:    String
        :param scan_date: The date from the scan which the user wants to obtain the result.
        :type scan_date:  Date
        :param app_key:   The key of the app which the user wants to obtain the result.
        :type app_key:    String
        :param lang:      The language in which the user wants to get the analysis result.
        :type lang:       "en", "es"
        :param workgroup: The workgroup where the user belongs to. (Not mandatory)
        :type workgroup:  String
        :return:          The response to the authenticated request **/scanResults**
                          to the mASAPP API, which returns the result of the mASAPPs analysis for the scan with
                          the scan_id, scan_date and app_key introduced, including **vulnerabilities and behaviors**
                          among other things.
        """
        LANGUAGES = ["en", "es"]

        if not lang in LANGUAGES:
            raise ValueError(
                "Language {language} Only supported languages: {langs}".format(language=lang, langs=LANGUAGES))

        if workgroup is None:
            return self.get(url_path=self.API_SCAN_RESULT,
                            authentication_instances=[self.authentication_instances],
                            query_params={'scanId': scan_id, 'scanDate': scan_date, 'appKey': app_key, 'lang': lang})

        else:
            return self.get(url_path=self.API_SCAN_RESULT,
                            authentication_instances=[self.authentication_instances],
                            headers={'wg': workgroup},
                            query_params={'scanId': scan_id, 'scanDate': scan_date, 'appKey': app_key, 'lang': lang})
