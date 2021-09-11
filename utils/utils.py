import boto3
import time

def credential_report():

    client = boto3.client('iam')

    try:
        return client.get_credential_report()
    except:
        print("Generating Credential Report")
        while True:
            if client.generate_credential_report()["State"] == "COMPLETE":
                return client.get_credential_report()
                break
            time.sleep(3)

def password_policy():
    client = boto3.client('iam')
    try:
        return client.get_account_password_policy()["PasswordPolicy"]
    # botocore.errorfactory.NoSuchEntityException: An error occurred (NoSuchEntity) when calling the GetAccountPasswordPolicy operation:
    except:
        # No password policy created
        return False

def account_summary():
    client = boto3.client('iam')    
    return client.get_account_summary()["SummaryMap"]

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
    
def list_buckets():
    # returns list of s3 buckets names
    client = boto3.client('s3')
    return [ bucket["Name"] for bucket in client.list_buckets()["Buckets"] ]