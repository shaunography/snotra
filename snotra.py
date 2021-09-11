#!/usr/bin/python3

import argparse
import boto3
import json
import os

from datetime import datetime

from checks.checks import checks

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

    for check in checks.cis(checks):
        results["findings"] += [ check() ]

    filename = os.path.join(args.o, "results_{}.json".format(get_account_id()))
    with open(filename, 'w') as f:
        json.dump(results, f)

if __name__ == '__main__':
    main()
