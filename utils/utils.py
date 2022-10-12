import boto3
import time
import sys
import logging

def get_user(session):
    client = session.client('sts') 
    return client.get_caller_identity()["Arn"]

def get_account_id(session):
    client = session.client('sts') 
    return client.get_caller_identity()["Account"]

def describe_regions(session):
    # returns list of available ec2 regions
    client = session.client('ec2', region_name="eu-west-2") # configure default region!
    try:
        regions = client.describe_regions()["Regions"]
    except boto3.exceptions.botocore.exceptions.ClientError as e:
        logging.error("Error getting regions - %s" % e.response["Error"]["Code"])
        if e.response["Error"]["Code"] == "UnauthorizedOperation":
                logging.error("Unauthorized Operation! - Check your credentials have the required policies applied before running Snotra")
                sys.exit(0)
    return  [ region["RegionName"] for region in regions ]

def get_available_regions_ec2(session):
    # returns list of available ec2 regions
    return session.get_available_regions(service_name="ec2")
