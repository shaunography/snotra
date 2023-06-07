#!/usr/bin/python3

import argparse
import boto3
import json
import os
import sys
import logging

from datetime import datetime
from datetime import date

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

from utils.utils import get_user
from utils.utils import get_account_id



def assume_role(role_arn=None, session_name='my_session'):
    """
    If role_arn is given assumes a role and returns boto3 session
    otherwise return a regular session with the current IAM user/role
    """
    if role_arn:
        client = boto3.client('sts')
        response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'])
        return session
    else:
        return boto3.Session()


def lambda_handler(event, context):

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s : %(levelname)s : %(funcName)s - %(message)s"
    )

    role_arn = event["role_arn"]
    session_name = event["session_name"]

    session = assume_role(role_arn, session_name)
    
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
    
    logging.info("writing results json S3")

    account_id = get_account_id(session)

    # session in lambda account to save to bucket
    session = boto3.session.Session()
    client = session.client('s3')
    client.put_object(Body=json.dumps(results),Bucket="snotra-results",Key="snotra_results_{}_{}.json".format(account_id, str(date.today())))

