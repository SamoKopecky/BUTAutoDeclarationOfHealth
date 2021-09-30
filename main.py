#!/usr/bin/env python3

import argparse
import json
import logging
import re
import sys
import traceback
from getpass import getpass

import requests


def parse_args(arguments):
    parser = argparse.ArgumentParser(usage='use -h or --help for more information',
                                     description="Script for signing the Declaration of health form in BUT IS")
    parser.add_argument("-c", "--credentials", action="store", metavar="path", required=False,
                        help="path to the file with your vut login credentials")
    parser.add_argument("-lf", "--log-file", action="store", metavar="path", required=False,
                        help="file for storing logs")
    parser.add_argument("-ss", "--short-stay", action="store_true", default=False,
                        help="check the option for a stay shorted then 12 hours")
    return parser.parse_args(arguments)


def get_credentials(file_path):
    if file_path is None:
        login = input("VUT login: ")
        passwd = getpass("VUT Password: ")
    else:
        credentials_dict = read_json(file_path)
        login = credentials_dict["login"]
        passwd = credentials_dict["passwd"]
    return login, passwd


def read_json(path):
    file = open(path, "r")
    json_data = json.loads(file.read())
    file.close()
    return json_data


def create_session(credentials):
    vut_session = requests.Session()
    form_data = {
        'special_p4_form': '1',
        'login_form': '1',
        'LDAPlogin': f'{credentials[0]}',
        'LDAPpasswd': f'{credentials[1]}',
    }
    # To get the vut_ack cookie
    vut_session.get('https://www.vut.cz/login')
    # Actual login
    vut_session.post('https://www.vut.cz/login/in/', data=form_data)
    if "portal_is_logged_in" not in vut_session.cookies.get_dict().keys():
        logging.error("Login failed")
        sys.exit(1)
    logging.info("Login successful")
    return vut_session


def sign_form(vut_session, args):
    # To get xs form id
    response = vut_session.get("https://www.vut.cz/studis/student.phtml?sn=prohlaseni_studenta")
    xs_id = re.findall('name="xs_prohlaseni__o__bezinfekcnosti__2" value="(.*?)"', response.text)
    if len(xs_id) == 0:
        logging.error("Sign form not found. Form was probably already signed today.")
        sys.exit(1)
    data = {
        "formID": "prohlaseni-o-bezinfekcnosti-2",
        "xs_prohlaseni__o__bezinfekcnosti__2": xs_id[0],
        "prijezdNa24h-2": f"{int(args.short_stay)}",
        "btnPodepsat-2": "1"
    }
    # Actual signing
    response = vut_session.post("https://www.vut.cz/studis/student.phtml?sn=prohlaseni_studenta", data=data)
    result_alert = re.findall('class="alert alert-success".*?class="alert-text"><div>(.*?)<\/div>', response)
    logging.info(f"Signing successful with the alert message: {result_alert[0]}")


def main():
    args = parse_args(sys.argv[1:])
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=args.log_file,
        level=logging.INFO)
    credentials = get_credentials(args.credentials)
    try:
        session = create_session(credentials)
        sign_form(session, args)
        session.close()
    except Exception:
        tb = traceback.format_exc()
        logging.error(tb)


if __name__ == "__main__":
    main()
