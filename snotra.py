#!/usr/bin/python3

import argparse
import boto3
import json
import os
import time

from checks.cis import cis

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
    filename = os.path.join(args.o, "CIS_Benchark.csv")
    
    with open(filename, 'w') as f:
        f.write("Check,Level,Benchmark,Result,Pass/Fail\n")

        for check in cis.checks(cis):
            results = check()
            print("running CIS check {}".format(results["check"]))
            f.write("{},{},{},{},{}\n".format(results["check"],results["level"],results["benchmark"],results["result"],results["pass_fail"]))

if __name__ == '__main__':
    main()