#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import getpass
import json
import sys
import os

from masappci import mASAPP_CI

ASCII_ART_DESCRIPTION = U'''
                        _____           _____   _____      _____  _____ 
                /\     / ____|   /\    |  __ \ |  __ \    / ____||_   _|
  _ __ ___     /  \   | (___    /  \   | |__) || |__) |  | |       | |  
 | '_ ` _ \   / /\ \   \___ \  / /\ \  |  ___/ |  ___/   | |       | |  
 | | | | | | / ____ \  ____) |/ ____ \ | |     | |       | |____  _| |_ 
 |_| |_| |_|/_/    \_\|_____//_/    \_\|_|     |_|        \_____||_____|

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

    args = parser.parse_args()

    ### Password setting ###
    masapp_key = None
    masapp_secret = None

    if args.configure:
        print("[?] Insert your MASSAP Access Key: ")
        masapp_key = str(sys.stdin.readline())
        os.environ["MASAPP_KEY"] = masapp_key

        masapp_secret = str(getpass.getpass(prompt='[?] Insert your MASSAP Secret Key: '))
        os.environ["MASAPP_SECRET"] = masapp_secret

        print("[!] Credentials loaded")
        # TODO maybe make it persistent

    elif (args.key and not args.secret) or (args.secret and not args.key):
        print("[X] -key and -secret can only be used simultaneously")

    elif args.key and args.secret:
        masapp_key = args.key
        masapp_secret = args.secret

    else:
        if os.getenv("MASAPP_KEY"):
            masapp_key = os.getenv("MASAPP_KEY")
        else:
            print(
                "[X] MASAPP_KEY is not stored in environment. Please, use the option --configure or add directly it with -key option")

        if os.getenv("MASAPP_SECRET"):
            masapp_secret = os.getenv("MASAPP_KEY")
        else:
            print(
                "[X] MASAPP_SECRET is not stored in environment. Please, use the option --configure or add directly it with -secret option")

    if masapp_key is not None and masapp_secret is not None:

        if args.riskscore and args.standard:
            print("[X] Riskscore and standard execution can not being thrown simultaneously")
            parser.print_help()
            return False

        elif args.riskscore:
            user = mASAPP_CI(key=masapp_key, secret=masapp_secret)

            if args.app:
                if args.packageNameOrigin:
                    user.riskscoring_execution(maximum_riskscoring=args.riskscore, app_path=args.app,
                                               package_name_origin=args.packageNameOrigin,
                                               detail=args.detailed)
                else:
                    user.riskscoring_execution(maximum_riskscoring=args.riskscore, app_path=args.app,
                                               detail=args.detailed)
            else:
                print("[X] No path to the app added")

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
                                                        detail=args.detailed)

                            else:
                                user.standard_execution(scan_maximum_values=checked_json, app_path=args.app,
                                                        detail=args.detailed)
                    else:
                        print("[X] Wrong json added for standard execution")
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
                    print("[X] No path to the app added")

            else:
                print("[X] No execution mode added")
    else:
        print("[X] mASAPP credentials not successfully set")


def main():
    cli(sys.argv[1:])


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
