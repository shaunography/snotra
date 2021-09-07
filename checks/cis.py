import boto3
import json
import re

from datetime import date
from datetime import timedelta

from utils.utils import credential_report
from utils.utils import password_policy
from utils.utils import account_summary
from utils.utils import describe_regions
from utils.utils import get_available_regions_ec2
from utils.utils import list_buckets


###
#
#    cis_dict = {
#        "id" : "cis",
#        "ref" : "",
#        "compliance" : "cis",
#        "level" : ,
#        "service" : ""
#        "name" : "",
#        "affected" : ""
#        "analysis" : "",
#        "description" : "",
#        "remediation" : "",
#        "impact" : "",
#        "probability" : "",
#        "cvss_vector" : "",
#        "cvss_score" : "",
#        "pass_fail" : ""
#    }
#
###



class cis():
    #def __init__(self):

    def CIS1_1():
        # Maintain current contact details (Manual)
        cis_dict = {
            "id" : "cis1",
            "ref" : "1.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Maintain current contact details",
            "affected": "",
            "analysis" : "Manual Check",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : ""
        }
        return cis_dict


    def CIS1_2():
        # Ensure security contact information is registered (Manual)
        cis_dict = {
            "id" : "cis2",
            "ref" : "1.2",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure security contact information is registered",
            "affected": "",
            "analysis" : "Manual Check",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : ""
        }
        return cis_dict

    def CIS1_3():
        # Ensure security questions are registered in the AWS account (Manual)
        cis_dict = {
            "id" : "cis3",
            "ref" : "1.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure security questions are registered in the AWS account",
            "affected": "",
            "analysis" : "Manual Check",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : ""
        }
        return cis_dict

    def CIS1_4():
        # Ensure no 'root' user account access key exists (Automated)
        
        cis_dict = {
            "id" : "cis4",
            "ref" : "1.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure no 'root' user account access key exists",
            "affected": "",
            "analysis" : "No root access keys exist",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        summary = account_summary()

        if summary["AccountAccessKeysPresent"] != 0:
            cis_dict["analysis"] = "Root Access Keys Found"
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict

    def CIS1_5():
        # Ensure MFA is enabled for the 'root' user account (Automated)
        
        cis_dict = {
            "id" : "cis5",
            "ref" : "1.5",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure MFA is enabled for the 'root' user account",
            "affected": "",
            "analysis" : "Root MFA is enabled",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        summary = account_summary()

        if summary["AccountMFAEnabled"] == 0:
            cis_dict["analysis"] = "Root MFA Not Enabled"
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict

    def CIS1_6():
        # Ensure hardware MFA is enabled for the 'root' user account (Automated)

        cis_dict = {
            "id" : "cis6",
            "ref" : "1.6",
            "compliance" : "cis",
            "level" : 2,
            "service" : "iam",
            "name" : "Ensure hardware MFA is enabled for the 'root' user account",
            "affected": "",
            "analysis" : "Root MFA is enabled (Virtual or Hardware)",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        summary = account_summary()

        if summary["AccountMFAEnabled"] == 0:
            cis_dict["analysis"] = "Root MFA Not Enabled"
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict


    def CIS1_7():
        # Eliminate use of the 'root' user for administrative and daily tasks (Automated)

        cis_dict = {
            "id" : "cis7",
            "ref" : "1.7",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Eliminate use of the 'root' user for administrative and daily tasks",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "INFO"
        }

        report_content = credential_report()["Content"].decode('ascii')
        root = report_content.split("\n")[1]
        password_last_used = root.split(",")[4]
        accesskey1_last_used = root.split(",")[10]
        accesskey2_last_used = root.split(",")[15]
        cis_dict["analysis"] = "password last used: {} Access Key 1 last used: {} Access Key 2 last used: {}".format(password_last_used, accesskey1_last_used, accesskey2_last_used)

        return cis_dict

    def CIS1_8():
        # Ensure IAM password policy requires minimum length of 14 or greater (Automated)

        cis_dict = {
            "id" : "cis8",
            "ref" : "1.8",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure IAM password policy requires minimum length of 14 or greater",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        password_length = password_policy()["MinimumPasswordLength"]
        if password_length < 14:
            cis_dict["analysis"] = "Minimum Password Length = {}".format(password_length)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS1_9():
        # Ensure IAM password policy prevents password reuse (Automated)

        cis_dict = {
            "id" : "cis9",
            "ref" : "1.9",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure IAM password policy prevents password reuse",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        try:
            password_reuse = password_policy()["PasswordReusePrevention"]
        except KeyError:
            cis_dict["analysis"] = "Password Reuse Prevention Not Set"
            cis_dict["pass_fail"] = "FAIL"
        else:
            if password_reuse < 24:
                cis_dict["analysis"] = "Password Reuse Prevention = {}".format(password_reuse)
                cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS1_10():
        # Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Automated)

        cis_dict = {
            "id" : "cis10",
            "ref" : "1.10",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        users = []

        report_content = credential_report()["Content"].decode('ascii')

        for user in report_content.split("\n"):
            password_enabled = user.split(",")[3]
            mfa_active = user.split(",")[7]
            
            if password_enabled == "true":
                if mfa_active == "false":
                    users += [user.split(",")[0]]
        
        if users:
            cis_dict["analysis"] = "The following users do not have MFA enabled: {}".format(" ".join(users))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict


    def CIS1_11():
        # Do not setup access keys during initial user setup for all IAM users that have a console password (Manual)
        
        cis_dict = {
            "id" : "cis11",
            "ref" : "1.11",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Do not setup access keys during initial user setup for all IAM users that have a console password",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        users = []

        report_content = credential_report()["Content"].decode('ascii')

        for user in report_content.split("\n"):
            password_enabled = user.split(",")[3]
            access_key_1_active = user.split(",")[8]
            access_key_1_last_used = user.split(",")[10]
            access_key_2_active = user.split(",")[13]
            access_key_2_last_used = user.split(",")[15]

            if password_enabled == "true":
                if access_key_1_active == "true" and access_key_1_last_used == "N/A":
                        users += [user.split(",")[0]]
                if access_key_2_active == "true" and access_key_2_last_used == "N/A":
                        users += [user.split(",")[0]]            
        
        if users:
            cis_dict["analysis"] = "The following users have unused Access Keys: {}".format(" ".join(users))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
    
    def CIS1_12():
        # Ensure credentials unused for 45 days or greater are disabled (Automated)

        cis_dict = {
            "id" : "cis12",
            "ref" : "1.12",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure credentials unused for 45 days or greater are disabled",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        users = []

        report_content = credential_report()["Content"].decode('ascii')

        for user in report_content.split("\n"):
            password_enabled = user.split(",")[3]
            password_last_used = user.split(",")[4]
            access_key_1_active = user.split(",")[8]
            access_key_1_last_used = user.split(",")[10]
            access_key_2_active = user.split(",")[13]
            access_key_2_last_used = user.split(",")[15]

            if password_enabled == "true":
                if password_last_used != "N/A":
                    year, month, day = password_last_used.split("T")[0].split("-")
                    password_last_used_date = date(int(year), int(month), int(day))
                    if password_last_used_date < (date.today() - timedelta(days=45)):
                        users += [user.split(",")[0]]

            if access_key_1_active == "true":
                if access_key_1_last_used != "N/A":
                    year, month, day = access_key_1_last_used.split("T")[0].split("-")
                    access_key_1_last_used_date = date(int(year), int(month), int(day))
                    if access_key_1_last_used_date < (date.today() - timedelta(days=45)):
                        users += [user.split(",")[0]]
            
            if access_key_2_active == "true":
                if access_key_2_last_used != "N/A":
                    year, month, day = access_key_2_last_used.split("T")[0].split("-")
                    access_key_2_last_used_date = date(int(year), int(month), int(day))
                    if access_key_2_last_used_date < (date.today() - timedelta(days=45)):
                        users += [user.split(",")[0]]

        if users:
            cis_dict["analysis"] = "The following users have credentials (password or keys) not used in the last 45 days: {}".format(" ".join(set(users)))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict



    def CIS1_13():
        # Ensure there is only one active access key available for any single IAM user (Automated)

        cis_dict = {
            "id" : "cis13",
            "ref" : "1.13",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure there is only one active access key available for any single IAM user",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        users = []

        report_content = credential_report()["Content"].decode('ascii')

        for user in report_content.split("\n"):
            access_key_1_active = user.split(",")[8]
            access_key_2_active = user.split(",")[13]

            if access_key_1_active == "true":
                if access_key_2_active == "true":
                        users += [user.split(",")[0]]

        if users:
            cis_dict["analysis"] = "The following users have more than one access key: {}".format(" ".join(users))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    
    
    def CIS1_14():
        # Ensure access keys are rotated every 90 days or less (Automated)

        cis_dict = {
            "id" : "cis14",
            "ref" : "1.14",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure access keys are rotated every 90 days or less",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        users = []

        report_content = credential_report()["Content"].decode('ascii')

        for user in report_content.split("\n"):
            access_key_1_active = user.split(",")[8]
            access_key_1_last_rotated = user.split(",")[9]
            access_key_2_active = user.split(",")[13]
            access_key_2_last_rotated = user.split(",")[14]

            if access_key_1_active == "true":
                if access_key_1_last_rotated != "N/A":
                    year, month, day = access_key_1_last_rotated.split("T")[0].split("-")
                    access_key_1_last_rotated_date = date(int(year), int(month), int(day))
                    if access_key_1_last_rotated_date < (date.today() - timedelta(days=90)):
                        users += [user.split(",")[0]]
            
            if access_key_2_active == "true":
                if access_key_2_last_rotated != "N/A":
                    year, month, day = access_key_2_last_rotated.split("T")[0].split("-")
                    access_key_2_last_rotated_date = date(int(year), int(month), int(day))
                    if access_key_2_last_rotated_date < (date.today() - timedelta(days=90)):
                        users += [user.split(",")[0]]

        if users:
            cis_dict["analysis"] = "The following users have access keys that have not been rotated in the last 90 days: {}".format(" ".join(set(users)))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS1_15():
        # Ensure IAM Users Receive Permissions Only Through Groups (Automated)


        cis_dict = {
            "id" : "cis15",
            "ref" : "1.15",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure IAM Users Receive Permissions Only Through Groups",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        client = boto3.client('iam')

        all_users = client.list_users()["Users"]
        users = []

        for user in all_users:
            inline_policies = client.list_user_policies(UserName=user["UserName"])
            attached_policies = client.list_attached_user_policies(UserName=user["UserName"])

            if inline_policies["PolicyNames"]:
                    users += [user["UserName"]]
            
            if attached_policies["AttachedPolicies"]:
                    users += [user["UserName"]]

        if users:
            cis_dict["analysis"] = "The following users have managed or inline policies directly attached: {}".format(" ".join(set(users)))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
    
    def CIS1_16():
        # Ensure IAM policies that allow full "*:*" administrative privileges are not attached (Automated)

        cis_dict = {
            "id" : "cis16",
            "ref" : "1.16",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure IAM policies that allow full *:* administrative privileges are not attached",
            "affected": "",
            "analysis" : "No custom policies that allow full *:* privileges found",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        client = boto3.client('iam')

        all_policies = client.list_policies(OnlyAttached=True)["Policies"]
        policies = []

        for policy in all_policies:

            arn = policy["Arn"]
            policy_name = policy["PolicyName"]
            #policy_id = policy["PolicyId"]
            version_id = policy["DefaultVersionId"]

            statements = client.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"]["Document"]["Statement"]
            for statement in statements:
                if statement["Effect"] == "Allow":
                    if statement["Action"] == "*":
                        if statement["Resource"] == "*":
                            policies += []

        if policies:
            cis_dict["analysis"] = "The following customer policies grant full *:* privileges: {}".format(" ".join(set(policies)))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS1_17():
        # Ensure a support role has been created to manage incidents with AWS Support (Automated)


        cis_dict = {
            "id" : "cis17",
            "ref" : "1.17",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure a support role has been created to manage incidents with AWS Support",
            "affected": "",
            "analysis" : "AWSSupportAccess Policy is not attached to any entities",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        client = boto3.client('iam')

        #all_policies = client.list_policies(Scope="All")["Policies"]
        attached_policies = client.list_policies(OnlyAttached=True)["Policies"]

        for policy in attached_policies:
            
            if policy["PolicyName"] == "AWSSupportAccess":                
                cis_dict["analysis"] = "AWSSupportAccess Policy is attached - but not to a custom support role"
                cis_dict["pass_fail"] = "FAIL"
                
                arn = policy["Arn"]
                
                policy_roles = client.list_entities_for_policy(PolicyArn=arn)["PolicyRoles"]
                
                if policy_roles:
                    cis_dict["analysis"] = "AWSSupportAccess Policy is attached to role: {}".format(" ".join(policy_roles))
                    cis_dict["pass_fail"] = "PASS"

        return cis_dict

    def CIS1_18():
        # Ensure IAM instance roles are used for AWS resource access from instances (Manual)

        cis_dict = {
            "id" : "cis18",
            "ref" : "1.18",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure IAM instance roles are used for AWS resource access from instances",
            "affected": "",
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        failing_instances = []
        regions = describe_regions()

        for region in regions:
            client = boto3.client('ec2', region_name=region)
            instance_description = client.describe_instances()
            reservations = instance_description["Reservations"]
            for reservation in reservations:
                instances = reservation["Instances"]
                for instance in instances:
                    state = instance["State"]["Name"]
                    if state == "running":
                        instance_id = instance["InstanceId"]
                        ec2 = boto3.resource('ec2', region_name=region)
                        ec2_instance = ec2.Instance(id=instance_id)
                        if not ec2_instance.iam_instance_profile:
                            failing_instances += ["{}({})".format(instance_id, region)]

        if failing_instances:
            cis_dict["analysis"] = "the following running instances do not have an instance profile attached: {}".format(" ".join(failing_instances))
            cis_dict["affected"] = ", ".join(failing_instances)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict


    def CIS1_19():
        # Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed (Automated)

        cis_dict = {
            "id" : "cis19",
            "ref" : "1.19",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
            "affected": "",
            "analysis" : "No expired server certificates found",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        client = boto3.client('iam')
        server_certificates = client.list_server_certificates()["ServerCertificateMetadataList"]
        expired_certs = []

        if not server_certificates:
            cis_dict["analysis"] = "No server certificates found"
            cis_dict["pass_fail"] = "PASS"
        
        #############################################
        # NEEDS TESTING WITH ACTUAL EXPIRED CERTS!!!#
        #############################################
        for cert in server_certificates:
            expiration = cert["Expiration"]
            server_certificate_name = cert["ServerCertificateName"]
            year, month, day = expiration.split("T")[0].split("-")
            expiration_date = date(int(year), int(month), int(day))
            if expiration_date < date.today():
                expired_certs += [server_certificate_name]

        if expired_certs:
            cis_dict["analysis"] = "the following server certificates have expired: {}".format(" ".join(expired_certs))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS1_20():
        # Ensure that IAM Access analyzer is enabled for all regions (Automated)

        cis_dict = {
            "id" : "cis20",
            "ref" : "1.20",
            "compliance" : "cis",
            "level" : 1,
            "service" : "access_analyzer",
            "name" : "Ensure that IAM Access analyzer is enabled for all regions",
            "affected": "",
            "analysis" : "Access Analyzer is enabled in all regions",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }


        failing_regions = []
        regions = describe_regions()

        for region in regions:
            client = boto3.client('accessanalyzer', region_name=region)
            if not client.list_analyzers()["analyzers"]:
                failing_regions += [region]

        if failing_regions:
            cis_dict["analysis"] = "the following regions do not have Access Analyzer enabled: {}".format(" ".join(failing_regions))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS1_21():
        # Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments (Manual)

        # could list identity providers and local iam users for comparison

        cis_dict = {
            "id" : "cis21",
            "ref" : "1.21",
            "compliance" : "cis",
            "level" : 2,
            "service" : "iam",
            "name" : "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
            "affected": "",
            "analysis" : "Manual Check",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : ""
        }

        return cis_dict

    def CIS2_1_1():
        # Ensure all S3 buckets employ encryption-at-rest (Manual)

        cis_dict = {
            "id" : "cis22",
            "ref" : "2.1.1",
            "compliance" : "cis",
            "level" : 2,
            "service" : "s3",
            "name" : "Ensure all S3 buckets employ encryption-at-rest",
            "affected": "",
            "analysis" : "All buckets have server side encryption enabled",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        client = boto3.client('s3')
        failing_buckets = []

        for bucket in list_buckets():
            try:
                encryption = client.get_bucket_encryption(Bucket=bucket)
            # ServerSideEncryptionConfigurationNotFoundError
            # botocore.exceptions.ClientError: An error occurred (ServerSideEncryptionConfigurationNotFoundError) when calling the GetBucketEncryption operation: The server side encryption configuration was not found
            except:
                failing_buckets += [bucket]

        if failing_buckets:
            cis_dict["analysis"] = "the following buckets do not have server side encryption enabled: {}".format(" ".join(failing_buckets))
            cis_dict["affected"] = ", ".join(failing_buckets)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    
    def CIS2_1_2():
        # Ensure S3 Bucket Policy is set to deny HTTP requests (Manual)

        cis_dict = {
            "id" : "cis23",
            "ref" : "2.1.2",
            "compliance" : "cis",
            "level" : 2,
            "service" : "s3",
            "name" : "Ensure S3 Bucket Policy is set to deny HTTP requests",
            "affected": "",
            "analysis" : "All buckets enforce HTTPS requests",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }
        
        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/checks/check_extra764

        client = boto3.client('s3')
        passing_buckets = []      
        buckets = list_buckets()

        for bucket in buckets:
            try:
                policy = json.loads(client.get_bucket_policy(Bucket=bucket)["Policy"])
            # botocore.exceptions.ClientError: An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist
            except:
                pass
            else:
                statements = policy["Statement"]
                for statement in statements:
                    try:
                        bool_secure_transport = statement["Condition"]["Bool"]["aws:SecureTransport"]
                    except KeyError:
                        pass
                    else:
                        effect = statement["Effect"]
                        action = statement["Action"]
                        resource = statement["Resource"]
                        if bool_secure_transport == "false":
                            if effect == "Deny":
                                if action == "s3:GetObject" or action == "s3:*":
                                    if re.match("arn:aws:s3*|\*", resource):
                                        passing_buckets += [bucket]

        failing_buckets = [i for i in buckets if i not in passing_buckets]
        
        if failing_buckets:
            cis_dict["analysis"] = "the following buckets do enfore HTTPS requests: {}".format(" ".join(failing_buckets))
            cis_dict["affected"] = ", ".join(failing_buckets)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS2_1_3():
        # Ensure MFA Delete is enable on S3 buckets (Automated)

        cis_dict = {
            "id" : "cis24",
            "ref" : "2.1.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure MFA Delete is enable on S3 buckets",
            "affected": "",
            "analysis" : "All buckets have MFA Delete Enabled",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        client = boto3.client('s3')
        passing_buckets = []      
        buckets = list_buckets()

        for bucket in buckets:
            try:
                if client.get_bucket_versioning(Bucket=bucket)["Status"] == "Enabled":
                    if client.get_bucket_versioning(Bucket=bucket)["MfaDelete"] == "Enabled": # need testing with mfadelete enabled bucket
                        passing_buckets += [bucket]
            except KeyError:
                pass
            
        failing_buckets = [i for i in buckets if i not in passing_buckets]
        
        if failing_buckets:
            cis_dict["analysis"] = "the following buckets do have MFA Delete enabled: {}".format(" ".join(failing_buckets))
            cis_dict["affected"] = ", ".join(failing_buckets)
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict


    def CIS2_1_4():
        # Ensure all data in Amazon S3 has been discovered, classified and secured when required. (Manual)

        cis_dict = {
            "id" : "cis25",
            "ref" : "2.1.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure all data in Amazon S3 has been discovered, classified and secured when required",
            "affected": "",
            "analysis" : "Manual Check",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : ""
        }

        #client = boto3.client('macie2', region_name="eu-west-2")

        return cis_dict

    def CIS2_1_5():
        # Ensure that S3 Buckets are configured with 'Block public access (bucket settings)' (Automated)

        cis_dict = {
            "id" : "cis26",
            "ref" : "2.1.5",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure that S3 Buckets are configured with Block public access (bucket settings)",
            "affected": "",
            "analysis" : "All Buckets block public access ",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        client = boto3.client('s3')
        passing_buckets = []      
        buckets = list_buckets()

        for bucket in buckets:
            try:
                public_access_block_configuration = client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                if public_access_block_configuration["BlockPublicAcls"] == True:
                    if public_access_block_configuration["IgnorePublicAcls"] == True:
                        if public_access_block_configuration["BlockPublicPolicy"] == True:
                            if public_access_block_configuration["RestrictPublicBuckets"] == True:
                                passing_buckets += [bucket]
            #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
            except:
                pass

        failing_buckets = [i for i in buckets if i not in passing_buckets]
        
        if failing_buckets:
            cis_dict["analysis"] = "the following buckets do not block public access: {}".format(" ".join(failing_buckets))
            cis_dict["affected"] = ", ".join(failing_buckets)
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict


    def CIS2_2_1():
        # Ensure EBS volume encryption is enabled (Manual)

        cis_dict = {
            "id" : "cis27",
            "ref" : "2.2.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure EBS volume encryption is enabled",
            "affected": "",
            "analysis" : "All EBS Volumes are encrypted",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        #regions = get_available_regions_ec2()
        regions = describe_regions()
        failing_regions = []
        
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            if client.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] == False:
                failing_regions += [region]
        
        if failing_regions:
            cis_dict["analysis"] = "the following EC2 regions do not encrypt EBS volumes by default: {}".format(" ".join(failing_regions))
            cis_dict["affected"] = ", ".join(failing_regions)
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict


    def CIS2_3_1():
        # Ensure that encryption is enabled for RDS Instances (Automated)

        cis_dict = {
            "id" : "cis28",
            "ref" : "2.3.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "rds",
            "name" : "Ensure that encryption is enabled for RDS Instances",
            "affected": "",
            "analysis" : "All RDS instances have encryption enabled",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_instances = []
        
        for region in regions:
            client = boto3.client('rds', region_name=region)
            instances = client.describe_db_instances()["DBInstances"]
            for instance in instances:
                db_instance_identifier = instance["DBInstanceIdentifier"]
                instance_description = client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)["DBInstances"][0]
                if instance_description["StorageEncrypted"] != True:
                    failing_instances += [db_instance_identifier]

        if failing_instances:
            cis_dict["analysis"] = "the following EC2 regions do not encrypt EBS volumes by default: {}".format(" ".join(failing_instances))
            cis_dict["affected"] = ", ".join(failing_instances)
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict