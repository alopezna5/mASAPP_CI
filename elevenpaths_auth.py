#!/usr/bin/python
# -*- coding: utf-8 -*-

from sdklib.http import HttpSdk
from sdklib.http.authorization import X11PathsAuthentication


class mASAPP_CI_auth(HttpSdk):
    """
        Class that contains the necessary authorization for working with mASAPP API
    """

    API_VERSION = "1.6.2"
    DEFAULT_HOST = "https://masapp.elevenpaths.com"
    API_WORKGROUPS = "/api/{api_version}/workgroups".format(api_version=API_VERSION)
    API_UPLOAD = "/api/{api_version}/upload".format(api_version=API_VERSION)
    API_SCANS = "/api/{api_version}/scans".format(api_version=API_VERSION)
    API_SCAN_SUMMARY = "/api/{api_version}/scanSummary?scanId=".format(api_version=API_VERSION)
    API_SCAN_RESULT = "/api/{api_version}/scanResults".format(api_version=API_VERSION)

    def __init__(self, key, secret):
        self.authentication_instances = X11PathsAuthentication(key, secret)
        super(mASAPP_CI_auth, self).__init__()

    def get_auth_workgroup(self):
        """
        :return:
        """
        return self.get(url_path=self.API_WORKGROUPS, authentication_instances=[self.authentication_instances])

    def post_auth_upload_app(self, workgroup, allowTacyt, app_path):
        """
        :param workgroup:
        :param allowTacyt:
        :param app:
        :return:
        """
        body_params = {
            "allowTacyt": allowTacyt
        }

        return self.post(url_path=self.API_UPLOAD, authentication_instances=[self.authentication_instances],
                         headers={'wg': workgroup}, body_params=body_params, files={'file': app_path})

    def get_auth_scans(self, workgroup):
        """
        :param workgroup:
        :return:
        """
        return self.get(url_path=self.API_SCANS, authentication_instances=[self.authentication_instances],
                        headers={'wg': workgroup})

    def get_scan_summary(self, workgroup, scan_id):
        """
        :param workgroup:
        :param scan_id:
        :return:
        """
        return self.get(url_path=self.API_SCAN_SUMMARY + scan_id,
                        authentication_instances=[self.authentication_instances],
                        headers={'wg': workgroup})

    def get_scan_result(self, workgroup, scan_id, scan_date, app_key, lang):
        """
        :param workgroup:
        :param scan_id:
        :param scan_date:
        :param app_key:
        :param lang:
        :return:
        """

        return self.get(url_path=self.API_SCAN_RESULT,
                        authentication_instances=[self.authentication_instances],
                        headers={'wg': workgroup},
                        query_params={'scanId': scan_id, 'scanDate': scan_date, 'appKey': app_key, 'lang': lang})

