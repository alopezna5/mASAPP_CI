#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import json
from masappci import mASAPP_CI

ASCII_ART_DESCRIPTION = U'''
                        _____           _____   _____      _____  _____ 
                /\     / ____|   /\    |  __ \ |  __ \    / ____||_   _|
  _ __ ___     /  \   | (___    /  \   | |__) || |__) |  | |       | |  
 | '_ ` _ \   / /\ \   \___ \  / /\ \  |  ___/ |  ___/   | |       | |  
 | | | | | | / ____ \  ____) |/ ____ \ | |     | |       | |____  _| |_ 
 |_| |_| |_|/_/    \_\|_____//_/    \_\|_|     |_|        \_____||_____|

'''



def masappci_cli():
    parser = argparse.ArgumentParser(prog='masappci', description=ASCII_ART_DESCRIPTION,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-a', '--app', help='path to the .apk or .ipa file', metavar=".ipa/.apk",
                        required=True)
    parser.add_argument('-p', '--packageNameOrigin', help='package name origin of the app')
    parser.add_argument('-r', '--riskscore', help='riskscoring execution', type=float, metavar="N")
    parser.add_argument('-d', '--detailed', help='add details to the execution', action='store_true')
    parser.add_argument('-s', '--standard', help='standard execution', metavar=".json")

    args = parser.parse_args()

    if args.riskscore:
        user = mASAPP_CI(key="", secret="")
        if args.packageNameOrigin:
            user.riskscoring_execution(maximum_riskscoring=args.riskscore, app_path=args.app,
                                       package_name_origin=args.packageNameOrigin,
                                       detail=args.detailed)
        else:
            user.riskscoring_execution(maximum_riskscoring=args.riskscore, app_path=args.app, detail=args.detailed)


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
            checked_json = check_json(args.standard)
            if checked_json:
                user = mASAPP_CI(key="", secret="")

                if type(checked_json) != bool:
                    user.standard_execution(checked_json, args.app, "com.andreea.android.dev.triplelayerGooglePlay",
                                            detail=args.detailed)

            else:
                print(
                    u"""
                        -s --standard json structure:
                            {
                              "vulnerabilities": {
                                "critical": maximum of critical vulnerabilities,
                                "high": maximum of high vulnerabilities,
                                "medium": maximum of medium vulnerabilities,
                                "low": maximum of low vulnerabilities
                              },
                              "behaviorals": {
                                "critical": maximum of critical behaviorals,
                                "high": "maximum of high behaviorals,
                                "medium": maximum of medium behavioral,
                                "low": maximum of low behaviorals
                              }
                            }     
                    """
                )


        else:
            parser.print_help()


if __name__ == '__main__':
    masappci_cli()

