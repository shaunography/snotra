#!/usr/bin/python3

import argparse
import boto3
import json
import os
import time

from checks.checks import checks
#from checks.cis import cis

from utils.utils import get_user

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
    
    print("Running test with: {}".format(get_user()["Arn"]))
    
    
    # CIS Audit CSV    
    filename = os.path.join(args.o, "CIS_Benchark.csv")

    with open(filename, 'w') as f:
        f.write("Check,Level,Benchmark,Result,Pass/Fail\n")

        for check in checks.cis(checks):
            results = check()
            print("CIS check {} complete".format(results["ref"]))
            f.write("{},{},{},{},{}\n".format(results["ref"],results["level"],results["name"],results["analysis"],results["pass_fail"]))

if __name__ == '__main__':
    main()
    