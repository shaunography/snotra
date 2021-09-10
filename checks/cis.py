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
     
        if password_policy():
            password_length = password_policy()["MinimumPasswordLength"]        
            cis_dict["analysis"] = "Minimum Password Length = {}".format(password_length)
            if password_length < 14:
                cis_dict["pass_fail"] = "FAIL"
        else:
            cis_dict["analysis"] = "No password policy configured"
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

        if password_policy():
            try:
                password_reuse = password_policy()["PasswordReusePrevention"]
            except KeyError:
                cis_dict["analysis"] = "Password Reuse Prevention Not Set"
                cis_dict["pass_fail"] = "FAIL"
            else:
                cis_dict["analysis"] = "Password Reuse Prevention = {}".format(password_reuse)
                if password_reuse < 24:
                    cis_dict["pass_fail"] = "FAIL"
        else:
            cis_dict["analysis"] = "No password policy configured"
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
            "analysis" : "All users have MFA enabled",
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
            "analysis" : "No unused Access Keys found",
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
            "analysis" : "No unused credentials found",
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
            "analysis" : "No used with more than one access key found",
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
            "analysis" : "No keys that have not been rotated found",
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
            "analysis" : "No directly attached policies found",
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
            cis_dict["analysis"] = "The following custom policies grant full *:* privileges: {}".format(" ".join(set(policies)))
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
            except boto3.exceptions.botocore.exceptions.ClientError:
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
            except boto3.exceptions.botocore.exceptions.ClientError:
                # no bucket policy exists
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
            "name" : "Ensure all data in Amazon S3 has been discovered classified and secured when required",
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
            #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
            except boto3.exceptions.botocore.exceptions.ClientError:
                # no public access block configuration exists
                pass
            else:
                if public_access_block_configuration["BlockPublicAcls"] == True:
                    if public_access_block_configuration["IgnorePublicAcls"] == True:
                        if public_access_block_configuration["BlockPublicPolicy"] == True:
                            if public_access_block_configuration["RestrictPublicBuckets"] == True:
                                passing_buckets += [bucket]

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


    def CIS3_1():
        # Ensure CloudTrail is enabled in all regions (Automated)

        cis_dict = {
            "id" : "cis29",
            "ref" : "3.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail is enabled in all regions",
            "affected": "",
            "analysis" : "No multi region enabled trails were found",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        regions = describe_regions()
        multi_region_trails = []
        
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                trail_name = trail["Name"]
                if trail["IsMultiRegionTrail"] == True:
                    if trail["HomeRegion"] == region:
                        if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                            multi_region_trails += [trail_name]

        if multi_region_trails:
            cis_dict["analysis"] = "the following trails are multi region enabled: {}".format(" ".join(multi_region_trails))
            #cis_dict["affected"] = ", ".join(multi_region_trails)
            cis_dict["pass_fail"] = "PASS"
        
        return cis_dict

    def CIS3_2():
        # Ensure CloudTrail log file validation is enabled (Automated)

        cis_dict = {
            "id" : "cis30",
            "ref" : "3.2",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail log file validation is enabled",
            "affected": "",
            "analysis" : "log file validation is enabled on all trails",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_trails = []
        
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["LogFileValidationEnabled"] == False:
                        failing_trails += [trail["Name"]]

        if failing_trails:
            cis_dict["analysis"] = "the following trails are multi region enabled: {}".format(" ".join(failing_trails))
            cis_dict["affected"] = ", ".join(failing_trails)
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict

    def CIS3_3():
        # Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible (Automated)

        cis_dict = {
            "id" : "cis31",
            "ref" : "3.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
            "affected": "",
            "analysis" : "no public cloud trail buckets found",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_trails = []

        s3_client = boto3.client('s3')
        
        for region in regions:
            cloudtrail_client = boto3.client('cloudtrail', region_name=region)
            trail_list = cloudtrail_client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    bucket_name = trail["S3BucketName"]
                    trail_name = trail["Name"]
                    grants = s3_client.get_bucket_acl(Bucket=bucket_name)["Grants"]
                    for grant in grants:
                        try:
                            if grant["Grantee"]["URI"] == "https://acs.amazonaws.com/groups/global/AllUsers":
                                failing_trails += [trail_name]
                            if grant["Grantee"]["URI"] == "https://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                                failing_trails += [trail_name]
                        except KeyError:
                            pass
                                     
                        try:
                            policy = json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"])
                        # botocore.exceptions.ClientError: An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist
                        except boto3.exceptions.botocore.exceptions.ClientError:
                            # no bucket policy exists
                            pass
                        else:
                            statements = policy["Statement"]
                            for statement in statements:
                                effect = statement["Effect"]
                                if effect == "Allow":
                                    try:
                                        if statement["Principal"]["AWS"] == "*":
                                            failing_trails += [trail_name]
                                    except KeyError:
                                        pass

                                    try:
                                        if statement["Principal"]["Service"] == "*":
                                            failing_trails += [trail_name]
                                    except KeyError:
                                        pass

        if failing_trails:
            cis_dict["analysis"] = "the following trails are using a potentially public S3 bucket: {}".format(" ".join(set(failing_trails)))
            cis_dict["affected"] = ", ".join(set(failing_trails))
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict



    def CIS3_4():
        # Ensure CloudTrail trails are integrated with CloudWatch Logs (Automated)

        cis_dict = {
            "id" : "cis32",
            "ref" : "3.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail trails are integrated with CloudWatch Logs",
            "affected": "",
            "analysis" : "all trails are integrated with CloudWatch Logs",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_trails = []
        
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                    except KeyError:
                        failing_trails += [trail["Name"]]

        if failing_trails:
            cis_dict["analysis"] = "the following trails are not integrated with CloudWatch Logs: {}".format(" ".join(failing_trails))
            cis_dict["affected"] = ", ".join(failing_trails)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict


    def CIS3_5():
        # Ensure AWS Config is enabled in all regions (Automated)

        cis_dict = {
            "id" : "cis33",
            "ref" : "3.5",
            "compliance" : "cis",
            "level" : 2,
            "service" : "config",
            "name" : "Ensure AWS Config is enabled in all regions",
            "affected": "",
            "analysis" : "AWS Config is enabled in all regions",
            "description" : "AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources. It is recommended AWS Config be enabled in all regions. The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing.",
            "remediation" : "It is recommended AWS Config be enabled in all regions.",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_regions = []
        
        for region in regions:
            client = boto3.client('config', region_name=region)
            recorder_list = client.describe_configuration_recorders()["ConfigurationRecorders"]
            if not recorder_list:
                failing_regions += [region]
            else:
                for recorder in recorder_list:
                    if recorder["recordingGroup"]["allSupported"] != True:
                        if recorder["recordingGroup"]["includeGlobalResourceTypes"] != True:
                            failing_regions += [region]

        if failing_regions:
            cis_dict["analysis"] = "the following regions do not have AWS config enabled: {}".format(" ".join(failing_regions))
            cis_dict["affected"] = ", ".join(failing_regions)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS3_6():
        # Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Automated)

        cis_dict = {
            "id" : "cis34",
            "ref" : "3.6",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
            "affected": "",
            "analysis" : "S3 bucket acces logging is enabled",
            "description" : "S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket. By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within any target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows.",
            "remediation" : "Ensure the CloudTrail S3 bucket has access logging is enabled",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_trails = []

        s3_client = boto3.client('s3')
        
        for region in regions:
            cloudtrail_client = boto3.client('cloudtrail', region_name=region)
            trail_list = cloudtrail_client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        logging = s3_client.get_bucket_logging(Bucket=trail["S3BucketName"])["LoggingEnabled"]
                    except KeyError:
                        failing_trails += [trail["Name"]]

        if failing_trails:
            cis_dict["analysis"] = "the following trails do not have S3 bucket access logging enabled: {}".format(" ".join(failing_trails))
            cis_dict["affected"] = ", ".join(failing_trails)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
    
    
    def CIS3_7():
        # Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Automated)

        cis_dict = {
            "id" : "cis35",
            "ref" : "3.7",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
            "affected": "",
            "analysis" : "CloudTrail logs are encrypted at rest with KMS CMKs",
            "description" : "AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS. Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data as a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.",
            "remediation" : "Configure CloudTrail to use SSE-KMS for encryption at rest.",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_trails = []
        
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        kms_key_id = trail["KmsKeyId"]
                    except KeyError:
                        failing_trails += [trail["Name"]]

        if failing_trails:
            cis_dict["analysis"] = "the following trails are multi region enabled: {}".format(" ".join(failing_trails))
            cis_dict["affected"] = ", ".join(failing_trails)
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict

    def CIS3_8():
        # Ensure rotation for customer created CMKs is enabled (Automated)

        cis_dict = {
            "id" : "cis36",
            "ref" : "3.8",
            "compliance" : "cis",
            "level" : 2,
            "service" : "kms",
            "name" : "Ensure rotation for customer created CMKs is enabled",
            "affected": "",
            "analysis" : "rotation is enabled on all CMKs",
            "description" : "AWS Key Management Service (KMS) allows customers to rotate the backing key which is key material stored within the KMS which is tied to the key ID of the Customer Created customer master key (CMK). It is the backing key that is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can take place transparently. It is recommended that CMK key rotation be enabled. Rotating encryption keys helps reduce the potential impact of a compromised key as data encrypted with a new key cannot be accessed with a previous key that may have been exposed.",
            "remediation" : "Enable key rotation on all customer created CMKs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_keys = []
        
        for region in regions:
            client = boto3.client('kms', region_name=region)
            keys_list = client.list_keys()["Keys"]
            for key in keys_list:
                key_id = key["KeyId"]
                try:
                    key_rotation_Status = client.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]
                #botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the GetKeyRotationStatus operation
                except boto3.exceptions.botocore.exceptions.ClientError:
                    print("access denied - KMS KeyID:{}({})".format(key_id, region))
                    pass
                else:
                    if key_rotation_Status == False:
                        failing_keys += ["{}({})".format(key_id, region)]

        if failing_keys:
            cis_dict["analysis"] = "the following KMS keys do not have rotation enabled: {}".format(" ".join(failing_keys))
            cis_dict["affected"] = ", ".join(failing_keys)
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict
    
    
    def CIS3_9():
        # Ensure VPC flow logging is enabled in all VPCs (Automated)

        cis_dict = {
            "id" : "cis37",
            "ref" : "3.9",
            "compliance" : "cis",
            "level" : 2,
            "service" : "vpc",
            "name" : "Ensure VPC flow logging is enabled in all VPCs",
            "affected": "",
            "analysis" : "Flow Logs are enabled on all VPCs",
            "description" : "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet Rejects for VPCs. VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.",
            "remediation" : "Enable VPC Flow Logs on all VPCs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_regions = []
        
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            flow_logs = client.describe_flow_logs()["FlowLogs"]
            if not flow_logs:
                failing_regions += [region]
            

        if failing_regions:
            cis_dict["analysis"] = "the following regions do not have any VPC FLow Logs enabled: {}".format(" ".join(failing_regions))
            cis_dict["affected"] = ", ".join(failing_regions)
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict
    
    
    def CIS3_10():
        # Ensure that Object-level logging for write events is enabled for S3 bucket (Automated)

        cis_dict = {
            "id" : "cis38",
            "ref" : "3.10",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure that Object-level logging for write events is enabled for S3 bucket",
            "affected": "",
            "analysis" : "No trails were found with S3 Object-Level Logging enabled",
            "description" : "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets. Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events.",
            "remediation" : "Enable S3 bucket Object-level logging for write events in CloudTrail",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }
        
        regions = describe_regions()
        passing_trails = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if trail["HasCustomEventSelectors"] == True:
                        trail_name = trail["Name"]
                        event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"]
                        for selector in event_selectors:
                            if selector["ReadWriteType"] == "All" or selector["ReadWriteType"] == "WriteOnly":
                                for resources in selector["DataResources"]:
                                    if resources["Type"] == "AWS::S3::Object":
                                        passing_trails += [trail_name]
        
        if passing_trails:
            cis_dict["analysis"] = "the following trails have S3 Object-Level logging enabled: {}".format(" ".join(passing_trails))
            cis_dict["affected"] = ", ".join(passing_trails)
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS3_11():
        # Ensure that Object-level logging for read events is enabled for S3 bucket (Automated)

        cis_dict = {
            "id" : "cis39",
            "ref" : "3.11",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure that Object-level logging for write read is enabled for S3 bucket",
            "affected": "",
            "analysis" : "No trails were found with S3 Object-Level Logging enabled",
            "description" : "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets. Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity using Amazon CloudWatch Events.",
            "remediation" : "Enable S3 bucket Object-level logging for read events in CloudTrail",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }
        
        regions = describe_regions()
        passing_trails = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if trail["HasCustomEventSelectors"] == True:
                        trail_name = trail["Name"]
                        event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"]
                        for selector in event_selectors:
                            if selector["ReadWriteType"] == "All" or selector["ReadWriteType"] == "ReadOnly":
                                for resources in selector["DataResources"]:
                                    if resources["Type"] == "AWS::S3::Object":
                                        passing_trails += [trail_name]
        
        if passing_trails:
            cis_dict["analysis"] = "the following trails have S3 Object-Level logging enabled: {}".format(" ".join(passing_trails))
            cis_dict["affected"] = ", ".join(passing_trails)
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    
    def CIS4_1():
        # Ensure a log metric filter and alarm exist for unauthorized API calls (Automated)

        cis_dict = {
            "id" : "cis40",
            "ref" : "4.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for unauthorized API calls",
            "affected": "",
            "analysis" : "No log metric filter and alarm for unauthorized API calls could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for unauthorized API calls. Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity.",
            "remediation" : "Create a log metric filter and alarm for unauthorized API calls in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []

        ## What a mess, could probably be moved into a seperate function to be shared with the other metric/alarm checks
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") || ($.sourceIPAddress!="delivery.logs.amazonaws.com") || ($.eventName!="HeadBucket") }
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*UnauthorizedOperation.*)(?:.*AccessDenied.*)(?:.*"delivery.logs.amazonaws.com".*)(?:.*"HeadBucket".*)'
                                                if re.match(regex, metric_filter_pattern):

                                                    # check alarm exists for filter
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for unauthorized API calls: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict


    def CIS4_2():
        # Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Automated)

        cis_dict = {
            "id" : "cis41",
            "ref" : "4.2",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA",
            "affected": "",
            "analysis" : "No log metric filter and alarm for Management Console sign-in without MFA could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for console logins that are not protected by multi-factor authentication (MFA). Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA.",
            "remediation" : "Create a log metric filter and alarm for Management Console sign-in without MFA in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }
                                                metric_filter_pattern = filter["filterPattern"]

                                                regex = '(?:.*"ConsoleLogin".*)(?:.*MFAUsed.*Yes.*)(?:.*"IAMUser".*)(?:.*"Success".*)'
                                                if re.match(regex, metric_filter_pattern):

                                                    # check alarm exists for filter
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for Management Console sign-in without MFA: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
        
        
    def CIS4_3():
        # Ensure a log metric filter and alarm exist for usage of 'root' account (Automated)

        cis_dict = {
            "id" : "cis42",
            "ref" : "4.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for usage of root account",
            "affected": "",
            "analysis" : "No log metric filter and alarm for usage of 'root' account could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for 'root' login attempts. Monitoring for 'root' account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it.",
            "remediation" : "Create a log metric filter and alarm for usage of root account in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
                                                metric_filter_pattern = filter["filterPattern"]

                                                regex = '(?:.*userIdentity.type\s=\s"Root".*)(?:.*NOT\sEXISTS.*)(?:.*eventType\s!=\s"AwsServiceEvent".*)'
                                                if re.match(regex, metric_filter_pattern):
                                                            
                                                    # check alarm exists for filter
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for usage of 'root' account: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS4_4():
        # Ensure a log metric filter and alarm exist for IAM policy changes (Automated)

        cis_dict = {
            "id" : "cis43",
            "ref" : "4.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for IAM policy changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for IAM policy changes could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established changes made to Identity and Access Management (IAM) policies. Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact.",
            "remediation" : "Create a log metric filter and alarm for IAM policy changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # {($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = "(?:.*DeleteGroupPolicy.*)(?:.*DeleteRolePolicy.*)(?:.*DeleteUserPolicy.*)(?:.*PutGroupPolicy.*)(?:.*PutRolePolicy.*)(?:.*PutUserPolicy.*)(?:.*CreatePolicy.*)(?:.*DeletePolicy.*)(?:.*CreatePolicyVersion.*)(?:.*DeletePolicyVersion.*)(?:.*AttachRolePolicy.*)(?:.*DetachRolePolicy.*)(?:.*AttachUserPolicy.*)(?:.*DetachUserPolicy.*)(?:.*AttachGroupPolicy.*)(?:.*DetachGroupPolicy.*)"
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for for IAM policy changes: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS4_5():
        # Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Automated)

        cis_dict = {
            "id" : "cis44",
            "ref" : "4.5",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for CloudTrail configuration changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for CloudTrail configuration changes could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail's configurations. Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account.",
            "remediation" : "Create a log metric filter and alarm for CloudTrail configuration changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = "(?:.*CreateTrail.*)(?:.*UpdateTrail.*)(?:.*DeleteTrail.*)(?:.*StartLogging.*)(?:.*StopLogging.*)"
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for CloudTrail configuration changes: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS4_6():
        # Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Automated)

        cis_dict = {
            "id" : "cis45",
            "ref" : "4.6",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures",
            "affected": "",
            "analysis" : "No log metric filter and alarm for AWS Management Console authentication failures could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for failed console authentication attempts. Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation.",
            "remediation" : "Create a log metric filter and alarm for AWS Management Console authentication failures in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*eventName\s\=\sConsoleLogin.*)(?:.*errorMessage\s\=\s"Failed\sauthentication".*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for AWS Management Console authentication failures: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS4_7():
        # Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Automated)

        cis_dict = {
            "id" : "cis46",
            "ref" : "4.7",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs",
            "affected": "",
            "analysis" : "No log metric filter and alarm for disabling or scheduled deletion of customer created CMKs could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for customer created CMKs which have changed state to disabled or scheduled deletion. Data encrypted with disabled or deleted keys will no longer be accessible.",
            "remediation" : "Create a log metric filter and alarm for disabling or scheduled deletion of customer created CMKs in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*kms.amazonaws.com.*)(?:.*DisableKey.*)(?:.*ScheduleKeyDeletion.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for disabling or scheduled deletion of customer created CMKs: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict

    def CIS4_8():
        # Ensure a log metric filter and alarm exist for S3 bucket policy changes (Automated)

        cis_dict = {
            "id" : "cis47",
            "ref" : "4.8",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for S3 bucket policy changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for S3 bucket policy changes could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for changes to S3 bucket policies. Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets.",
            "remediation" : "Create a log metric filter and alarm for S3 bucket policy changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*s3.amazonaws.com.*)(?:.*PutBucketAcl.*)(?:.*PutBucketPolicy.*)(?:.*PutBucketCors.*)(?:.*PutBucketLifecycle.*)(?:.*PutBucketReplication.*)(?:.*DeleteBucketPolicy.*)(?:.*DeleteBucketCors.*)(?:.*DeleteBucketLifecycle.*)(?:.*DeleteBucketReplication.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for S3 bucket policy changes: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    
    def CIS4_9():
        # Ensure a log metric filter and alarm exist for AWS Config configuration changes (Automated)

        cis_dict = {
            "id" : "cis48",
            "ref" : "4.9",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for AWS Config configuration changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for AWS Config configuration changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail's configurations. Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account.",
            "remediation" : "Create a log metric filter and alarm for AWS Config configuration changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*config.amazonaws.com.*)(?:.*StopConfigurationRecorder.*)(?:.*DeleteDeliveryChannel.*)(?:.*PutDeliveryChannel.*)(?:.*PutConfigurationRecorder.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for AWS Config configuration changes: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict


    def CIS4_10():
        # Ensure a log metric filter and alarm exist for security group changes (Automated)

        cis_dict = {
            "id" : "cis49",
            "ref" : "4.10",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for security group changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for security group changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC. It is recommended that a metric filter and alarm be established for detecting changes to Security Groups. Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.",
            "remediation" : "Create a log metric filter and alarm for security group changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*AuthorizeSecurityGroupIngress.*)(?:.*AuthorizeSecurityGroupEgress.*)(?:.*RevokeSecurityGroupIngress.*)(?:.*RevokeSecurityGroupEgress.*)(?:.*CreateSecurityGroup.*)(?:.*DeleteSecurityGroup.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for security group changes: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    
    def CIS4_11():
        # Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Automated)

        cis_dict = {
            "id" : "cis50",
            "ref" : "4.11",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)",
            "affected": "",
            "analysis" : "No log metric filter and alarm for changes to Network Access Control Lists (NACL)",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC. It is recommended that a metric filter and alarm be established for detecting changes to Security Groups. Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.",
            "remediation" : "Create a log metric filter and alarm for changes to Network Access Control Lists (NACL) in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*CreateNetworkAcl.*)(?:.*CreateNetworkAclEntry.*)(?:.*DeleteNetworkAcl.*)(?:.*DeleteNetworkAclEntry.*)(?:.*ReplaceNetworkAclEntry.*)(?:.*ReplaceNetworkAclAssociation.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for changes to Network Access Control Lists (NACL): {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS4_12():
        # Ensure a log metric filter and alarm exist for changes to network gateways (Automated)

        cis_dict = {
            "id" : "cis51",
            "ref" : "4.12",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for changes to network gateways",
            "affected": "",
            "analysis" : "No log metric filter and alarm for changes to network gateways",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC. It is recommended that a metric filter and alarm be established for detecting changes to Security Groups. Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.",
            "remediation" : "Create a log metric filter and alarm for changes to network gateways in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*CreateCustomerGateway.*)(?:.*DeleteCustomerGateway.*)(?:.*AttachInternetGateway.*)(?:.*CreateInternetGateway.*)(?:.*DeleteInternetGateway.*)(?:.*DetachInternetGateway.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for changes to network gateways: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS4_13():
        # Ensure a log metric filter and alarm exist for route table changes (Automated)

        cis_dict = {
            "id" : "cis52",
            "ref" : "4.13",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for route table changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for route table changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables. Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path. ",
            "remediation" : "Create a log metric filter and alarm for route table changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*CreateRoute.*)(?:.*CreateRouteTable.*)(?:.*ReplaceRoute.*)(?:.*ReplaceRouteTableAssociation.*)(?:.*DeleteRouteTable.*)(?:.*DeleteRoute.*)(?:.*DisassociateRouteTable.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for route table changes: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS4_14():
        # Ensure a log metric filter and alarm exist for VPC changes (Automated)

        cis_dict = {
            "id" : "cis53",
            "ref" : "4.14",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for VPC changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for VPC changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is possible to have more than 1 VPC within an account, in addition it is also possible to create a peer connection between 2 VPCs enabling network traffic to route between VPCs. It is recommended that a metric filter and alarm be established for changes made to VPCs. Monitoring changes to VPC will help ensure VPC traffic flow is not getting impacted.",
            "remediation" : "Create a log metric filter and alarm for route table changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*CreateVpc.*)(?:.*DeleteVpc.*)(?:.*ModifyVpcAttribute.*)(?:.*AcceptVpcPeeringConnection.*)(?:.*CreateVpcPeeringConnection.*)(?:.*DeleteVpcPeeringConnection.*)(?:.*RejectVpcPeeringConnection.*)(?:.*AttachClassicLinkVpc.*)(?:.*DetachClassicLinkVpc.*)(?:.*DisableVpcClassicLink.*)(?:.*EnableVpcClassicLink.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for VPC changes: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict
    
    def CIS4_15():
        # Ensure a log metric filter and alarm exist for AWS Organizations changes (Automated)

        cis_dict = {
            "id" : "cis54",
            "ref" : "4.15",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for AWS Organizations changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for AWS Organizations changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for AWS Organizations changes made in the master AWS Account. Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches. This monitoring technique helps you to ensure that any unexpected changes performed within your AWS Organizations can be investigated and any unwanted changes can be rolled back.",
            "remediation" : "Create a log metric filter and alarm for route table changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        regions = describe_regions()
        passing_metrics = []
     
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            cis_dict["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            cis_dict["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*organizations.amazonaws.com.*)(?:.*"AcceptHandshake".*)(?:.*"AttachPolicy".*)(?:.*"CreateAccount".*)(?:.*"CreateOrganizationalUnit".*)(?:.*"CreatePolicy".*)(?:.*"DeclineHandshake".*)(?:.*"DeleteOrganization".*)(?:.*"DeleteOrganizationalUnit".*)(?:.*"DeletePolicy".*)(?:.*"DetachPolicy".*)(?:.*"DisablePolicyType".*)(?:.*"EnablePolicyType".*)(?:.*"InviteAccountToOrganization".*)(?:.*"LeaveOrganization".*)(?:.*"MoveAccount".*)(?:.*"RemoveAccountFromOrganization".*)(?:.*"UpdatePolicy".*)(?:.*"UpdateOrganizationalUnit".*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            cis_dict["analysis"] = "the following metric filters were found for AWS Organizations changes: {}".format(" ".join(passing_metrics))
            cis_dict["pass_fail"] = "PASS"

        return cis_dict


    def CIS5_1():
        # Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)

        cis_dict = {
            "id" : "cis55",
            "ref" : "5.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
            "affected": "",
            "analysis" : "No NACLs that allow remote server administration ingress traffic from 0.0.0.0/0 found",
            "description" : "The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389. Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow RDP and SSH traffic from a whitelist of trusted IP addresses",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_nacls = []
            
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            network_acls = client.describe_network_acls()["NetworkAcls"]
            for acl in network_acls:
                network_acl_id = acl["NetworkAclId"]
                entries = acl["Entries"]
                for entry in entries:
                    if entry["Egress"] == False:
                        if entry["RuleAction"] == "allow":
                            if entry["CidrBlock"] == "0.0.0.0/0":
                                failing_nacls += ["{}({})".format(network_acl_id, region)]
        if failing_nacls:
            cis_dict["analysis"] = "the following Network ACLs allow allow ingress traffic from 0.0.0.0/0: {}".format(" ".join(failing_nacls))
            cis_dict["pass_fail"] = "CHECK"

        return cis_dict


    def CIS5_2():
        # Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)

        cis_dict = {
            "id" : "cis56",
            "ref" : "5.2",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
            "affected": "",
            "analysis" : "No security groups that allow remote server administration ingress traffic from 0.0.0.0/0 found",
            "description" : "Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389 . Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow RDP and SSH traffic from a whitelist of trusted IP addresses",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_security_groups = []
            
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            security_groups = client.describe_security_groups()["SecurityGroups"]
            for group in security_groups:
                group_id = group["GroupId"]
                ip_permissions = group["IpPermissions"]
                for ip_permission in ip_permissions:
                    try:
                        if ip_permission["FromPort"] == 22 or ip_permission["FromPort"] == 3389:
                            for ip_range in ip_permission["IpRanges"]:
                                if ip_range["CidrIp"] == "0.0.0.0/0":
                                    failing_security_groups += ["{}({})".format(group_id, region)]
                    except KeyError:
                        pass

        if failing_security_groups:
            cis_dict["analysis"] = "the following security groups allow admin ingress traffic from 0.0.0.0/0: {}".format(" ".join(failing_security_groups))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
    
    
    def CIS5_3():
        # Ensure the default security group of every VPC restricts all traffic (Automated)

        cis_dict = {
            "id" : "cis57",
            "ref" : "5.3",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure the default security group of every VPC restricts all traffic",
            "affected": "",
            "analysis" : "default security groups restrict all traffic",
            "description" : "A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If you don't specify a security group when you launch an instance, the instance is automatically assigned to this default security group. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that the default security group restrict all traffic. The default VPC in every region should have its default security group updated to comply. Any newly created VPCs will automatically contain a default security group that will need remediation to comply with this recommendation. NOTE: When implementing this recommendation, VPC flow logging is invaluable in determining the least privilege port access required by systems to work properly because it can log all packet acceptances and rejections occurring under the current security groups. This dramatically reduces the primary barrier to least privilege engineering - discovering the minimum ports required by systems in the environment. Even if the VPC flow logging recommendation in this benchmark is not adopted as a permanent security measure, it should be used during any period of discovery and engineering for least privileged security groups. Configuring all VPC default security groups to restrict all traffic will encourage least privilege security group development and mindful placement of AWS resources into security groups which will in-turn reduce the exposure of those resources.",
            "remediation" : "Configure default security groups in all VPCs to be default deny and restrict all traffic",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        failing_security_groups = []
            
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            security_groups = client.describe_security_groups()["SecurityGroups"]
            for group in security_groups:
                group_id = group["GroupId"]
                if group["GroupName"] == "default":
                    if group["IpPermissions"]:
                        failing_security_groups += ["{}({})".format(group_id, region)]
                    
        if failing_security_groups:
            cis_dict["analysis"] = "the following default security groups have inbound rules configured: {}".format(" ".join(failing_security_groups))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
    
    def CIS5_4():
        # Ensure routing tables for VPC peering are "least access" (Manual)

        cis_dict = {
            "id" : "cis58",
            "ref" : "5.4",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure routing tables for VPC peering are least access",
            "affected": "",
            "analysis" : "VPC Peering not in use",
            "description" : "Once a VPC peering connection is established, routing tables must be updated to establish any connections between the peered VPCs. These routes can be as specific as desired - even peering a VPC to only a single host on the other side of the connection. Being highly selective in peering routing tables is a very effective way of minimizing the impact of breach as resources outside of these routes are inaccessible to the peered VPC.",
            "remediation" : "Configure routing tables for VPC perring following the principle of least access",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        regions = describe_regions()
        peering_connections = []
            
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            route_tables = client.describe_route_tables()["RouteTables"]
            for route_table in route_tables:
                for route in route_table["Routes"]:
                    try:
                        vpc_peering_connection_id = route["VpcPeeringConnectionId"]
                    except KeyError:
                        pass
                    else:
                        peering_connections += ["{}({})".format(vpc_peering_connection_id, region)]
                    
        if peering_connections:
            cis_dict["analysis"] = "VPC peering in use, check routing tables for least access: {}".format(" ".join(set(peering_connections)))
            cis_dict["pass_fail"] = "INFO"

        return cis_dict