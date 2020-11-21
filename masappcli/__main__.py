#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import getpass
import json
import sys
import os

from masappcli.masappcli import mASAPP_CI

ASCII_ART_DESCRIPTION = U'''
                        _____           _____   _____      _____  __      _____   
                /\     / ____|   /\    |  __ \ |  __ \    / ____||  |    |_   _|  
  _ __ ___     /  \   | (___    /  \   | |__) || |__) |  | |     |  |      | |    
 | '_ ` _ \   / /\ \   \___ \  / /\ \  |  ___/ |  ___/   | |     |  |      | |    
 | | | | | | / ____ \  ____) |/ ____ \ | |     | |       | |____ |  |___  _| |_   
 |_| |_| |_|/_/    \_\|_____//_/    \_\|_|     |_|        \_____||______||_____|  

'''


def cli(parser):
    if parser is None:
        raise TypeError("ERROR, parser is None")

    parser = argparse.ArgumentParser(prog='masappcli', description=ASCII_ART_DESCRIPTION,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-a', '--app', help='path to the .apk or .ipa file', metavar=".ipa/.apk")
    parser.add_argument('-key', type=str, metavar="mASAPP_key")
    parser.add_argument('-secret', type=str, metavar="mASAPP_secret")
    parser.add_argument('-p', '--packageNameOrigin', help='package name origin of the app', metavar="packageNameOrigin")
    parser.add_argument('-r', '--riskscore', help='riskscoring execution', type=float, metavar="N")
    parser.add_argument('-d', '--detailed', help='add details to the execution', action='store_true')
    parser.add_argument('-s', '--standard', help='standard execution', metavar=".json")
    parser.add_argument('-c', '--configure', help='add your mASAPP key and mASAPP secret as environment vars',
                        action='store_true')
    parser.add_argument('-w', '--workgroup', type=str, metavar="workgroup name",
                        help="the name of the workgroup you want to analyse in")
    parser.add_argument('--export_summary', help='export the scan summary from mASAPP in a json file', metavar="*.json")
    parser.add_argument('--export_result', help='export the scan result from mASAPP in a json file', metavar="*.json")

    args = parser.parse_args()

    print(ASCII_ART_DESCRIPTION)
    ### Password setting ###
    masapp_key = None
    masapp_secret = None

    if args.app is None and args.configure == False and args.detailed == False and args.key is None and args.packageNameOrigin is None and args.riskscore is None and args.secret is None and args.standard is None:
        raise ValueError("[X] No args added")

    if args.configure:
        print("[?] Insert your MASSAP Access Key: ")
        masapp_key = str(sys.stdin.readline())
        os.environ["MASAPP_KEY"] = masapp_key

        masapp_secret = str(getpass.getpass(prompt='[?] Insert your MASSAP Secret Key: '))
        os.environ["MASAPP_SECRET"] = masapp_secret

        print("[!] Credentials loaded")
        # TODO maybe make it persistent

    elif (args.key and not args.secret) or (args.secret and not args.key):
        raise ValueError("[X] -key and -secret can only be used simultaneously")

    elif args.key and args.secret:
        masapp_key = args.key
        masapp_secret = args.secret

    else:
        if os.getenv("MASAPP_KEY"):
            masapp_key = os.getenv("MASAPP_KEY")
        else:
            raise ValueError(
                "[X] MASAPP_KEY is not stored in environment. Please, use the option --configure or add directly it with -key option")

        if os.getenv("MASAPP_SECRET"):
            masapp_secret = os.getenv("MASAPP_SECRET")
        else:
            raise ValueError(
                "[X] MASAPP_SECRET is not stored in environment. Please, use the option --configure or add directly it with -secret option")

    if masapp_key is not None and masapp_secret is not None:
        workgroup = getattr(args, 'workgroup', None)

        if args.export_summary and args.export_result:
            if args.export_summary == args.export_result:
                raise ValueError("[X] Export files can not be named with the same name")

        if args.export_summary:
            if args.export_summary in os.listdir('.'):
                raise ValueError("[X] Export summary file already exists")

        if args.export_result:
            if args.export_result in os.listdir('.'):
                raise ValueError("[X] Export result file already exists")

        if args.riskscore and args.standard:
            raise ValueError("[X] Riskscore and standard execution can not being thrown simultaneously")

        elif args.riskscore:
            user = mASAPP_CI(key=masapp_key, secret=masapp_secret)

            if args.app:
                if args.packageNameOrigin:
                    user.riskscoring_execution(maximum_riskscoring=args.riskscore, app_path=args.app,
                                               package_name_origin=args.packageNameOrigin,
                                               workgroup=workgroup,
                                               detail=args.detailed,
                                               export_summary=args.export_summary,
                                               export_result=args.export_result
                                               )
                else:
                    user.riskscoring_execution(maximum_riskscoring=args.riskscore, app_path=args.app,
                                               workgroup=workgroup,
                                               detail=args.detailed,
                                               export_summary=args.export_summary,
                                               export_result=args.export_result
                                               )
            else:
                raise ValueError("[X] No path to the app added")

        else:

            if args.standard:
                if args.app:
                    checked_json = check_json(args.standard)
                    if checked_json:
                        user = mASAPP_CI(key=masapp_key, secret=masapp_secret)

                        if type(checked_json) != bool:
                            if args.packageNameOrigin:
                                user.standard_execution(scan_maximum_values=checked_json, app_path=args.app,
                                                        package_name_origin=args.packageNameOrigin,
                                                        workgroup=workgroup,
                                                        detail=args.detailed,
                                                        export_summary=args.export_summary,
                                                        export_result=args.export_result
                                                        )

                            else:
                                user.standard_execution(scan_maximum_values=checked_json, app_path=args.app,
                                                        workgroup=workgroup,
                                                        detail=args.detailed,
                                                        export_summary=args.export_summary,
                                                        export_result=args.export_result
                                                        )
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
                        raise ValueError("[X] Wrong json added for standard execution")
                else:
                    raise ValueError("[X] No path to the app added")

            else:
                raise ValueError("[X] No execution mode added")
    else:
        raise ValueError("[X] mASAPP credentials not successfully set")


def main():
    try:
        cli(sys.argv[1:])
    except Exception as e:
        print(e)
        sys.exit(-1)


def check_json(input_json):
    if input_json is not None:

        if ".json" in input_json:
            try:
                json_file = open(input_json)
                input_json = json.load(json_file)
                json_file.close()
            except:
                return False

        else:
            try:
                input_json = json.loads(input_json)
            except:
                return False

        keys = input_json.keys()

        correct_json = True

        for key in keys:
            if not key == "vulnerabilities" and not key == "behaviorals":
                correct_json = False

        if not correct_json:
            return False
        else:
            return input_json

    return False


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        sys.exit(-1)
