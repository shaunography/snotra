#!/usr/bin/python3

import argparse
import boto3
import json
import os
import sys

from datetime import datetime

from checks.iam import iam
from checks.s3 import s3
from checks.ec2 import ec2
from checks.access_analyzer import access_analyzer
from checks.rds import rds
from checks.cloudtrail import cloudtrail
from checks.config import config
from checks.kms import kms
from checks.cloudwatch import cloudwatch
from checks.guardduty import guardduty
from checks.efs import efs
from checks.sns import sns

from utils.utils import get_user
from utils.utils import get_account_id

def main():
    parser = argparse.ArgumentParser(description="AWS Auditor")
    parser.add_argument(
        "--results-dir",
        help="results directory",
        dest="o",
        required=True,
        metavar="<results-dir>"
    ),
    parser.add_argument(
        "--profile",
        help="aws profile",
        dest="p",
        required=False,
        metavar="<profile>"
    )
    args = parser.parse_args()

    if args.p:
        try:
            session = boto3.session.Session(profile_name=args.p)
        except boto3.exceptions.botocore.exceptions.ProfileNotFound:
            print("profile not found! try harder...")
            sys.exit(0)
    else:        
        session = boto3.session.Session()
        if session.get_credentials() == None:
            print("you have not configured any default credentials in ~/.aws/credentials")
            sys.exit(0)
    
    # init results dictionary
    results = {}

    print("Running test with: {}".format(get_user(session)))

    results["account"] = get_account_id(session)
    results["user"] = get_user(session)
    results["datetime"] = str(datetime.today())
    
    results["findings"] = []
    results["findings"] += iam(session).run()
    results["findings"] += s3(session).run()
    results["findings"] += ec2(session).run()
    results["findings"] += access_analyzer(session).run()
    results["findings"] += rds(session).run()
    results["findings"] += cloudtrail(session).run()
    results["findings"] += config(session).run()
    results["findings"] += kms(session).run()
    results["findings"] += cloudwatch(session).run()
    results["findings"] += guardduty(session).run()
    results["findings"] += efs(session).run()
    results["findings"] += sns(session).run()

    if not os.path.exists(args.o):
        print("results dir does not exist, creating it for you")
        os.makedirs(args.o)
    
    print("writing results json")
    filename = os.path.join(args.o, "results_{}.json".format(get_account_id(session)))
    with open(filename, 'w') as f:
        json.dump(results, f)

if __name__ == '__main__':
    main()
