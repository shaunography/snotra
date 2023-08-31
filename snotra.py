#!/usr/bin/python3

import argparse
import boto3
import json
import os
import sys
import logging

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
from checks.securityhub import securityhub
from checks.elb import elb
from checks.ecr import ecr
from checks.route53 import route53
from checks.acm import acm
from checks.resource_explorer import resource_explorer
from checks.aws_lambda import aws_lambda
from checks.code_build import code_build
from checks.cloud_formation import cloud_formation
from checks.ssm import ssm
from checks.dynamo_db import dynamo_db

from utils.utils import get_user
from utils.utils import get_account_id

def main():

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s : %(levelname)s : %(funcName)s - %(message)s"
    )

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
    ),
    parser.add_argument(
        "--cis",
        help="do cis only scan",
        action="store_true",
        required=False
    )
    args = parser.parse_args()

    if args.p:
        try:
            session = boto3.session.Session(profile_name=args.p)
        except boto3.exceptions.botocore.exceptions.ProfileNotFound:
            logging.error("profile not found! try harder...")
            sys.exit(0)
    else:        
        session = boto3.session.Session()
        if session.get_credentials() == None:
            logging.error("you have not configured any default credentials in ~/.aws/credentials")
            sys.exit(0)
    
    # init results dictionary
    results = {}

    try:
        logging.info("Running test with {}".format(get_user(session)))
    except boto3.exceptions.botocore.exceptions.ClientError as e:
        logging.error("Client error - %s" % e.response["Error"]["Code"])
        sys.exit(0)

    results["account"] = get_account_id(session)
    results["user"] = get_user(session)
    results["datetime"] = str(datetime.today())
    results["findings"] = []
    
    if args.cis:
        logging.info("performing CIS scan")
        results["findings"] += iam(session).cis()
        results["findings"] += s3(session).cis()
        results["findings"] += ec2(session).cis()
        results["findings"] += access_analyzer(session).cis()
        results["findings"] += rds(session).cis()
        results["findings"] += cloudtrail(session).cis()
        results["findings"] += config(session).cis()
        results["findings"] += kms(session).cis()
        results["findings"] += cloudwatch(session).cis()
        results["findings"] += efs(session).cis()
        results["findings"] += securityhub(session).cis()
    else:
        logging.info("performing full scan")
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
        results["findings"] += securityhub(session).run()
        results["findings"] += elb(session).run()
        results["findings"] += ecr(session).run()
        results["findings"] += route53(session).run()
        results["findings"] += acm(session).run()
        results["findings"] += resource_explorer(session).run()
        results["findings"] += aws_lambda(session).run()
        results["findings"] += code_build(session).run()
        results["findings"] += cloud_formation(session).run()
        results["findings"] += ssm(session).run()
        results["findings"] += dynamo_db(session).run()

    if not os.path.exists(args.o):
        logging.info("results dir does not exist, creating it for you")
        os.makedirs(args.o)
    
    filename = os.path.join(args.o, "snotra_results_{}.json".format(get_account_id(session)))
    logging.info("writing results json {}".format(filename))
    with open(filename, 'w') as f:
        json.dump(results, f)

if __name__ == '__main__':
    main()
