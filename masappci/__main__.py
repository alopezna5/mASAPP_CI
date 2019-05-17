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


def main():
    parser = argparse.ArgumentParser(prog='masappci', description=ASCII_ART_DESCRIPTION,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-a', '--app', help='path to the .apk or .ipa file', metavar=".ipa/.apk",
                        required=True)
    parser.add_argument('-key', type=str, metavar="mASAPP_key", required=True)
    parser.add_argument('-secret', type=str, metavar="mASAPP_secret", required=True)
    parser.add_argument('-p', '--packageNameOrigin', help='package name origin of the app', metavar="packageNameOrigin")
    parser.add_argument('-r', '--riskscore', help='riskscoring execution', type=float, metavar="N")
    parser.add_argument('-d', '--detailed', help='add details to the execution', action='store_true')
    parser.add_argument('-s', '--standard', help='standard execution', metavar=".json")

    args = parser.parse_args()

    if args.riskscore and args.standard:
        print("Riskscore and standard execution can not being thrown simultaneously")
        parser.print_help()
        return False


    elif args.riskscore:
        user = mASAPP_CI(key=args.key, secret=args.secret)
        if args.packageNameOrigin:
            user.riskscoring_execution(maximum_riskscoring=args.riskscore, app_path=args.app,
                                       package_name_origin=args.packageNameOrigin,
                                       detail=args.detailed)
        else:
            user.riskscoring_execution(maximum_riskscoring=args.riskscore, app_path=args.app, detail=args.detailed)


    else:

        if args.standard:
            checked_json = check_json(args.standard)
            if checked_json:
                user = mASAPP_CI(key=args.key, secret=args.secret)

                if type(checked_json) != bool:
                    if args.packageNameOrigin:
                        user.standard_execution(scan_maximum_values=checked_json, app_path=args.app,
                                                package_name_origin=args.packageNameOrigin,
                                                detail=args.detailed)

                    else:
                        user.standard_execution(scan_maximum_values=checked_json, app_path=args.app,
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
                parser.print_help()


        else:
            parser.print_help()


def check_json(input_json):
    if input_json is not None:

        if ".json" in input_json:
            try:
                input_json = json.load(open(input_json))
            except:
                return False

        else:
            try:
                input_json = json.loads(input_json)
            except:
                return False

        keys = input_json.keys()
        correct_json = 'vulnerabilities' in keys or 'behaviorals' in keys

        if not correct_json:
            return False
        else:
            return input_json

    return False


if __name__ == "__main__":
    main()
