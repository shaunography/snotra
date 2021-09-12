import boto3
import time

from datetime import date
from datetime import timedelta

class iam(object):

    def __init__(self):
        self.client = self.get_client()
        self.account_summary = self.get_account_summary()
        self.credential_report = self.get_credential_report()
        self.password_policy = self.get_password_policy()
        self.users = self.list_users()
        self.policies = self.get_policies()

    def run(self):
        findings = []
        findings += [ self.iam_1() ]
        findings += [ self.iam_2() ]
        findings += [ self.iam_3() ]
        findings += [ self.iam_4() ]
        findings += [ self.iam_5() ]
        findings += [ self.iam_6() ]
        findings += [ self.iam_7() ]
        findings += [ self.iam_8() ]
        findings += [ self.iam_9() ]
        findings += [ self.iam_10() ]
        findings += [ self.iam_11() ]
        findings += [ self.iam_12() ]
        findings += [ self.iam_13() ]
        findings += [ self.iam_14() ]
        findings += [ self.iam_15() ]
        findings += [ self.iam_16() ]
        findings += [ self.iam_17() ]
        findings += [ self.iam_18() ]
        findings += [ self.iam_19() ]
        return findings

    def get_client(self):
        return boto3.client('iam')
    
    def get_account_summary(self):
        print("Getting Account Summary")
        return self.client.get_account_summary()["SummaryMap"]

    def get_credential_report(self):
        try:
            print("Getting Credential Report")
            return self.client.get_credential_report()
        except:
            print("Generating Credential Report")
            while True:
                if self.client.generate_credential_report()["State"] == "COMPLETE":
                    return self.client.get_credential_report()
                    break
                time.sleep(3)

    def get_password_policy(self):
        try:
            print("Getting Password Policy")
            return self.client.get_account_password_policy()["PasswordPolicy"]
        # botocore.errorfactory.NoSuchEntityException: An error occurred (NoSuchEntity) when calling the GetAccountPasswordPolicy operation:
        except:
            # No password policy created
            return False

    def list_users(self):
        print("Getting User List")
        return self.client.list_users()["Users"]
    
    def get_policies(self):
        print("Getting Policies")
        return self.client.list_policies(OnlyAttached=True)["Policies"]

    def iam_1(self):
        # Maintain current contact details (Manual)
        results = {
            "id" : "iam_1",
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

        print("running check: iam_1")

        return results


    def iam_2(self):
        # Ensure security contact information is registered (Manual)
        results = {
            "id" : "iam_2",
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

        print("running check: iam_2")

        return results

    def iam_3(self):
        # Ensure security questions are registered in the AWS account (Manual)
        results = {
            "id" : "iam_3",
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

        print("running check: iam_3")

        return results

    def iam_4(self):
        # Ensure no 'root' user account access key exists (Automated)
        
        results = {
            "id" : "iam_4",
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

        print("running check: iam_4")

        if self.account_summary["AccountAccessKeysPresent"] != 0:
            results["analysis"] = "Root Access Keys Found"
            results["pass_fail"] = "FAIL"
        
        return results

    def iam_5(self):
        # Ensure MFA is enabled for the 'root' user account (Automated)
        
        results = {
            "id" : "iam_5",
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

        print("running check: iam_5")

        if self.account_summary["AccountMFAEnabled"] == 0:
            results["analysis"] = "Root MFA Not Enabled"
            results["pass_fail"] = "FAIL"
        
        return results

    def iam_6(self):
        # Ensure hardware MFA is enabled for the 'root' user account (Automated)

        results = {
            "id" : "iam_6",
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

        print("running check: iam_6")

        if self.account_summary["AccountMFAEnabled"] == 0:
            results["analysis"] = "Root MFA Not Enabled"
            results["pass_fail"] = "FAIL"
        
        return results


    def iam_7(self):
        # Eliminate use of the 'root' user for administrative and daily tasks (Automated)

        results = {
            "id" : "iam_7",
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

        print("running check: iam_7")

        report_content = self.credential_report["Content"].decode('ascii')
        root = report_content.split("\n")[1]
        password_last_used = root.split(",")[4]
        accesskey1_last_used = root.split(",")[10]
        accesskey2_last_used = root.split(",")[15]
        results["analysis"] = "password last used: {} Access Key 1 last used: {} Access Key 2 last used: {}".format(password_last_used, accesskey1_last_used, accesskey2_last_used)

        return results

    def iam_8(self):
        # Ensure IAM password policy requires minimum length of 14 or greater (Automated)

        results = {
            "id" : "iam_8",
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

        print("running check: iam_8")
     
        if self.password_policy:
            password_length = self.password_policy["MinimumPasswordLength"]        
            results["analysis"] = "Minimum Password Length = {}".format(password_length)
            if password_length < 14:
                results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No password policy configured"
            results["pass_fail"] = "FAIL"


        return results

    def iam_9(self):
        # Ensure IAM password policy prevents password reuse (Automated)

        results = {
            "id" : "iam_9",
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

        print("running check: iam_9")

        if self.password_policy:
            try:
                password_reuse = self.password_policy["PasswordReusePrevention"]
            except KeyError:
                results["analysis"] = "Password Reuse Prevention Not Set"
                results["pass_fail"] = "FAIL"
            else:
                results["analysis"] = "Password Reuse Prevention = {}".format(password_reuse)
                if password_reuse < 24:
                    results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No password policy configured"
            results["pass_fail"] = "FAIL"

        return results

    def iam_10(self):
        # Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Automated)

        results = {
            "id" : "iam_10",
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

        print("running check: iam_10")

        failing_users = []
        report_content = self.credential_report["Content"].decode('ascii')

        for user in report_content.split("\n"):
            password_enabled = user.split(",")[3]
            mfa_active = user.split(",")[7]
            
            if password_enabled == "true":
                if mfa_active == "false":
                    failing_users += [user.split(",")[0]]
        
        if failing_users:
            results["analysis"] = "The following users do not have MFA enabled: {}".format(" ".join(failing_users))
            results["pass_fail"] = "FAIL"

        return results


    def iam_11(self):
        # Do not setup access keys during initial user setup for all IAM users that have a console password (Manual)
        
        results = {
            "id" : "iam_11",
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

        print("running check: iam_11")

        failing_users = []
        report_content = self.credential_report["Content"].decode('ascii')

        for user in report_content.split("\n"):
            password_enabled = user.split(",")[3]
            access_key_1_active = user.split(",")[8]
            access_key_1_last_used = user.split(",")[10]
            access_key_2_active = user.split(",")[13]
            access_key_2_last_used = user.split(",")[15]

            if password_enabled == "true":
                if access_key_1_active == "true" and access_key_1_last_used == "N/A":
                        failing_users += [user.split(",")[0]]
                if access_key_2_active == "true" and access_key_2_last_used == "N/A":
                        failing_users += [user.split(",")[0]]            
        
        if failing_users:
            results["analysis"] = "The following users have unused Access Keys: {}".format(" ".join(failing_users))
            results["pass_fail"] = "FAIL"

        return results
    
    def iam_12(self):
        # Ensure credentials unused for 45 days or greater are disabled (Automated)

        results = {
            "id" : "iam_12",
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

        print("running check: iam_12")
        failing_users = []

        report_content = self.credential_report["Content"].decode('ascii')

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
                        failing_users += [user.split(",")[0]]

            if access_key_1_active == "true":
                if access_key_1_last_used != "N/A":
                    year, month, day = access_key_1_last_used.split("T")[0].split("-")
                    access_key_1_last_used_date = date(int(year), int(month), int(day))
                    if access_key_1_last_used_date < (date.today() - timedelta(days=45)):
                        failing_users += [user.split(",")[0]]
            
            if access_key_2_active == "true":
                if access_key_2_last_used != "N/A":
                    year, month, day = access_key_2_last_used.split("T")[0].split("-")
                    access_key_2_last_used_date = date(int(year), int(month), int(day))
                    if access_key_2_last_used_date < (date.today() - timedelta(days=45)):
                        failing_users += [user.split(",")[0]]

        if failing_users:
            results["analysis"] = "The following users have credentials (password or keys) not used in the last 45 days: {}".format(" ".join(set(failing_users)))
            results["pass_fail"] = "FAIL"

        return results



    def iam_13(self):
        # Ensure there is only one active access key available for any single IAM user (Automated)

        results = {
            "id" : "iam_13",
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

        print("running check: iam_13")

        failing_users = []
        report_content = self.credential_report["Content"].decode('ascii')

        for user in report_content.split("\n"):
            access_key_1_active = user.split(",")[8]
            access_key_2_active = user.split(",")[13]

            if access_key_1_active == "true":
                if access_key_2_active == "true":
                        failing_users += [user.split(",")[0]]

        if failing_users:
            results["analysis"] = "The following users have more than one access key: {}".format(" ".join(failing_users))
            results["pass_fail"] = "FAIL"

        return results

    
    
    def iam_14(self):
        # Ensure access keys are rotated every 90 days or less (Automated)

        results = {
            "id" : "iam_14",
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

        print("running check: iam_14")

        failing_users = []
        report_content = self.credential_report["Content"].decode('ascii')

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
                        failing_users += [user.split(",")[0]]
            
            if access_key_2_active == "true":
                if access_key_2_last_rotated != "N/A":
                    year, month, day = access_key_2_last_rotated.split("T")[0].split("-")
                    access_key_2_last_rotated_date = date(int(year), int(month), int(day))
                    if access_key_2_last_rotated_date < (date.today() - timedelta(days=90)):
                        failing_users += [user.split(",")[0]]

        if failing_users:
            results["analysis"] = "The following users have access keys that have not been rotated in the last 90 days: {}".format(" ".join(set(failing_users)))
            results["pass_fail"] = "FAIL"

        return results

    def iam_15(self):
        # Ensure IAM Users Receive Permissions Only Through Groups (Automated)

        results = {
            "id" : "iam_15",
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

        print("running check: iam_15")

        failing_users = []

        for user in self.users:
            inline_policies = self.client.list_user_policies(UserName=user["UserName"])
            attached_policies = self.client.list_attached_user_policies(UserName=user["UserName"])

            if inline_policies["PolicyNames"]:
                failing_users += [user["UserName"]]
            
            if attached_policies["AttachedPolicies"]:
                failing_users += [user["UserName"]]

        if failing_users:
            results["analysis"] = "The following users have managed or inline policies directly attached: {}".format(" ".join(set(failing_users)))
            results["pass_fail"] = "FAIL"

        return results
    
    def iam_16(self):
        # Ensure IAM policies that allow full "*:*" administrative privileges are not attached (Automated)

        results = {
            "id" : "iam_16",
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

        print("running check: iam_16")

        failing_policies = []

        for policy in self.policies:

            arn = policy["Arn"]
            policy_name = policy["PolicyName"]
            #policy_id = policy["PolicyId"]
            version_id = policy["DefaultVersionId"]

            statements = self.client.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"]["Document"]["Statement"]
            for statement in statements:
                if statement["Effect"] == "Allow":
                    if statement["Action"] == "*":
                        if statement["Resource"] == "*":
                            failing_policies += []

        if failing_policies:
            results["analysis"] = "The following custom policies grant full *:* privileges: {}".format(" ".join(set(failing_policies)))
            results["pass_fail"] = "FAIL"

        return results

    def iam_17(self):
        # Ensure a support role has been created to manage incidents with AWS Support (Automated)

        results = {
            "id" : "iam_17",
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

        print("running check: iam_17")

        for policy in self.policies:
            
            if policy["PolicyName"] == "AWSSupportAccess":                
                results["analysis"] = "AWSSupportAccess Policy is attached - but not to a custom support role"
                results["pass_fail"] = "FAIL"
                
                arn = policy["Arn"]
                
                policy_roles = self.client.list_entities_for_policy(PolicyArn=arn)["PolicyRoles"]
                
                if policy_roles:
                    results["analysis"] = "AWSSupportAccess Policy is attached to role: {}".format(" ".join(policy_roles))
                    results["pass_fail"] = "PASS"

        return results


    def iam_18(self):
        # Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed (Automated)

        results = {
            "id" : "iam_18",
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

        print("running check: iam_18")

        server_certificates = self.client.list_server_certificates()["ServerCertificateMetadataList"]
        expired_certs = []

        if not server_certificates:
            results["analysis"] = "No server certificates found"
            results["pass_fail"] = "PASS"
        
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
            results["analysis"] = "the following server certificates have expired: {}".format(" ".join(expired_certs))
            results["pass_fail"] = "FAIL"

        return results

    def iam_19(self):
        # Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments (Manual)

        # could list identity providers and local iam users for comparison

        results = {
            "id" : "iam_19",
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

        print("running check: iam_19")

        return results