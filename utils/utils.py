import boto3
import time

def get_user():
    client = boto3.client('sts')    
    return client.get_caller_identity()["Arn"]

def get_account_id():
    client = boto3.client('sts')    
    return client.get_caller_identity()["Account"]

def describe_regions():
    # returns list of available ec2 regions
    client = boto3.client('ec2', region_name="eu-west-2") # configure default region!
    regions = client.describe_regions()["Regions"]
    return  [ region["RegionName"] for region in regions ]

def get_available_regions_ec2():
    # returns list of available ec2 regions
    session = boto3.session.Session()
    return session.get_available_regions(service_name="ec2")
