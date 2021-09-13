#!/usr/bin/python3

import argparse
import boto3
import json
import os

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

from utils.utils import get_user
from utils.utils import get_account_id

def main():
    parser = argparse.ArgumentParser(description="AWS Auditor")
    parser.add_argument(
        "--output-dir",
        help="output dir",
        dest="o",
        required=True,
        metavar="output"
    )
    args = parser.parse_args()
    
    results = {}

    print("Running test with: {}".format(get_user()))

    results["account"] = get_account_id()
    results["user"] = get_user()
    results["datetime"] = str(datetime.today())
    
    results["findings"] = []
    results["findings"] += iam().run()
    results["findings"] += s3().run()
    results["findings"] += ec2().run()
    results["findings"] += access_analyzer().run()
    results["findings"] += rds().run()
    results["findings"] += cloudtrail().run()
    results["findings"] += config().run()
    results["findings"] += kms().run()
    results["findings"] += cloudwatch().run()
    results["findings"] += guardduty().run()
    results["findings"] += efs().run()

    filename = os.path.join(args.o, "results_{}.json".format(get_account_id()))
    with open(filename, 'w') as f:
        json.dump(results, f)

if __name__ == '__main__':
    main()
