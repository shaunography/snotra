import boto3
import time
import re
import json
import logging
import sys

from datetime import date
from datetime import timedelta

from utils.utils import get_account_id

class iam(object):

    def __init__(self, session):
        self.session = session
        self.account_id = get_account_id(session)
        self.client = self.get_client()
        self.account_summary = self.get_account_summary()
        self.credential_report = self.get_credential_report()
        self.password_policy = self.get_password_policy()
        self.users = self.list_users()
        self.aws_policies = self.get_aws_policies()
        self.customer_policies = self.get_customer_policies()
        self.groups = self.list_groups()
        self.roles = self.list_roles()

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
        findings += [ self.iam_20() ]
        findings += [ self.iam_21() ]
        findings += [ self.iam_22() ]
        findings += [ self.iam_23() ]
        return findings

    def get_client(self):
        return self.session.client('iam')
    
    def get_account_summary(self):
        logging.info("Getting Account Summary")
        try:
            return self.client.get_account_summary()["SummaryMap"]
        except boto3.exceptions.botocore.exceptions.ClientError as e:
            logging.error("Error getting certificate list - %s" % e.response["Error"]["Code"])
            if e.response["Error"]["Code"] == "AccessDenied":
                logging.error("Access Denied! - Check your credentials have the required policies applied before running Snotra")
                sys.exit(0)


    def get_credential_report(self):
        try:
            logging.info("Getting Credential Report")
            return self.client.get_credential_report()
        except:
            logging.info("Generating Credential Report")
            while True:
                if self.client.generate_credential_report()["State"] == "COMPLETE":
                    return self.client.get_credential_report()
                time.sleep(3)

    def get_password_policy(self):
        try:
            logging.info("Getting Password Policy")
            return self.client.get_account_password_policy()["PasswordPolicy"]
        except boto3.exceptions.botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity": # no password policy created
                return False

    def list_users(self):
        logging.info("Getting User List")
        try:
            return self.client.list_users()["Users"]
        except boto3.exceptions.botocore.exceptions.ClientError as e:
            logging.error("Error getting users - %s" % e.response["Error"]["Code"])
    
    def get_aws_policies(self):
        logging.info("Getting AWS Managed Policies")
        #return self.client.list_policies(OnlyAttached=True)["Policies"]
        policies = []
        try:
            current_policies = self.client.list_policies(Scope="AWS")
        except boto3.exceptions.botocore.exceptions.ClientError as e:
            logging.error("Error getting managed policies - %s" % e.response["Error"]["Code"])
        policies += current_policies["Policies"]
        is_truncated = current_policies["IsTruncated"]
        if is_truncated == True:
            while is_truncated == True:
                current_policies = self.client.list_policies(Scope="AWS", Marker=current_policies["Marker"])
                policies += current_policies["Policies"]
                is_truncated = current_policies["IsTruncated"]
        return policies
    
    def get_customer_policies(self):
        logging.info("Getting Customer Managed Policies")
        #return self.client.list_policies(OnlyAttached=True)["Policies"]
        policies = []
        try:
            current_policies = self.client.list_policies(Scope="Local")
        except boto3.exceptions.botocore.exceptions.ClientError as e:
            logging.error("Error getting customer managed policies - %s" % e.response["Error"]["Code"])
        policies += current_policies["Policies"]
        is_truncated = current_policies["IsTruncated"]
        if is_truncated == True:
            while is_truncated == True:
                try:
                    current_policies = self.client.list_policies(Scope="Local", Marker=current_policies["Marker"])
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting customer managed polcies - %s" % e.response["Error"]["Code"]) 
                policies += current_policies["Policies"]
                is_truncated = current_policies["IsTruncated"]
        return policies
    
    def list_groups(self):
        logging.info("Getting Groups")
        groups = []
        for group in self.client.list_groups()["Groups"]:
            try:
                raw_group = self.client.get_group(GroupName=group["GroupName"])
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting groups - %s" % e.response["Error"]["Code"])
            group = {} # only grap Group and User data discard the rest
            group["Group"] = raw_group["Group"]
            group["Users"] = raw_group["Users"]
            groups.append(group)
        return groups
    
    def list_roles(self):
        logging.info("Getting Roles")
        roles = []
        for role in self.client.list_roles()["Roles"]:
            try:
                roles.append(self.client.get_role(RoleName=role["RoleName"])["Role"])
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting roles - %s" % e.response["Error"]["Code"])
        return roles

    def iam_1(self):
        # Maintain current contact details (Manual)
        results = {
            "id" : "iam_1",
            "ref" : "1.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Maintain current contact details",
            "affected": [],
            "analysis" : "",
            "description" : "Ensure contact email and telephone details for AWS accounts are current and map to more than one individual in your organization. An AWS account supports a number of contact details, and AWS will use these to contact the account owner if activity judged to be in breach of Acceptable Use Policy or indicative of likely security compromise is observed by the AWS Abuse team. Contact details should not be for a single individual, as circumstances may arise where that individual is unavailable. Email contact details should point to a mail alias which forwards email to multiple individuals within the organization; where feasible, phone contact details should point to a PABX hunt group or other call-forwarding system. If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone using the contact details listed. If this is unsuccessful and the account behavior needs urgent mitigation, proactive measures may be taken, including throttling of traffic between the account exhibiting suspicious behavior and the AWS API endpoints and the Internet. This will result in impaired service to and from the account in question, so it is in both the customers' and AWS' best interests that prompt contact can be established. This is best achieved by setting AWS account contact details to point to resources which have multiple individuals as recipients, such as email aliases and PABX hunt groups.",
            "remediation" : "Ensure contact email and telephone details for AWS accounts are current",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = "Manual Check"
        results["pass_fail"] = "INFO"

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
            "affected": [],
            "analysis" : "",
            "description" : "AWS provides customers with the option of specifying the contact information for account's security team. It is recommended that this information be provided. Specifying security-specific contact information will help ensure that security advisories sent by AWS reach the team in your organization that is best equipped to respond to them.",
            "remediation" : "Ensure security contact information is registered",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = "Manual Check"
        results["pass_fail"] = "INFO"

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
            "affected": [],
            "analysis" : "",
            "description" : "The AWS support portal allows account owners to establish security questions that can be used to authenticate individuals calling AWS customer service for support. It is recommended that security questions be established. When creating a new AWS account, a default super user is automatically created. This account is referred to as the root user or root account. It is recommended that the use of this account be limited and highly controlled. During events in which the root password is no longer accessible or the MFA token associated with root is lost/destroyed it is possible, through authentication using secret questions and associated answers, to recover root user login access.",
            "remediation" : "Ensure security questions are registered in the AWS account",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = "Manual Check"
        results["pass_fail"] = "INFO"

        return results

    def iam_4(self):
        # Ensure no 'root' user account access key exists (Automated)
        
        results = {
            "id" : "iam_4",
            "ref" : "1.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "iam",
            "name" : "Ensure no root user account access key exists",
            "affected": [],
            "analysis" : "No root access keys exist",
            "description" : "The 'root' user account is the most privileged user in an AWS account. AWS Access Keys provide programmatic access to a given AWS account. It is recommended that all access keys associated with the root user account be removed. Removing access keys associated with the root user account limits vectors by which the account can be compromised. Additionally, removing the root access keys encourages the creation and use of role based accounts that are least privileged.",
            "remediation" : "Ensure no root user account access key exists",
            "impact" : "high",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score" : "8.1",
            "pass_fail" : "PASS"
        }

        logging.info(results["name"])

        if self.account_summary["AccountAccessKeysPresent"] != 0:
            results["analysis"] = "Root Access Keys Found"
            results["affected"].append(self.account_id)
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
            "name" : "Ensure MFA is enabled for the root user account",
            "affected": [],
            "analysis" : "Root MFA is enabled",
            "description" : "The 'root' user account is the most privileged user in an AWS account. Multi-factor Authentication (MFA) adds an extra layer of protection on top of a username and password. With MFA enabled, when a user signs in to an AWS website, they will be prompted for their username and password as well as for an authentication code from their AWS MFA device. Note: When virtual MFA is used for 'root' accounts, it is recommended that the device used is NOT a personal device, but rather a dedicated mobile device (tablet or phone) that is managed to be kept charged and secured independent of any individual personal devices. non-personal virtual MFA - This lessens the risks of losing access to the MFA due to device loss, device trade-in or if the individual owning the device is no longer employed at the company. Enabling MFA provides increased security for console access as it requires the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential.",
            "remediation" : "Enable MFA for the root user account",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : "PASS"
        }

        logging.info(results["name"])
        

        if self.account_summary["AccountMFAEnabled"] == 0:
            results["analysis"] = "Root MFA Not Enabled"
            results["affected"].append(self.account_id)
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
            "name" : "Ensure hardware MFA is enabled for the root user account",
            "affected": [],
            "analysis" : "Root MFA is enabled (Virtual or Hardware)",
            "description" : "The 'root' user account is the most privileged user in an AWS account. MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they will be prompted for their user name and password as well as for an authentication code from their AWS MFA device. For Level 2, it is recommended that the root user account be protected with a hardware MFA. A hardware MFA has a smaller attack surface than a virtual MFA. For example, a hardware MFA does not suffer the attack surface introduced by the mobile smartphone on which a virtual MFA resides. Note: Using hardware MFA for many, many AWS accounts may create a logistical device management issue. If this is the case, consider implementing this Level 2 recommendation selectively to the highest security AWS accounts and the Level 1 recommendation applied to the remaining accounts.",
            "remediation" : "Ensure hardware MFA is enabled for the root user account",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : "PASS"
        }

        logging.info(results["name"])
        

        if self.account_summary["AccountMFAEnabled"] == 0:
            results["analysis"] = "Root MFA Not Enabled"
            results["affected"].append(self.account_id)
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
            "affected": [],
            "analysis" : "",
            "description" : "With the creation of an AWS account, a 'root user' is created that cannot be disabled or deleted. That user has unrestricted access to and control over all resources in the AWS account. It is highly recommended that the use of this account be avoided for everyday tasks. The root user has unrestricted access to and control over all account resources. Use of it is inconsistent with the principles of least privilege and separation of duties, and can lead to unnecessary harm due to error or account compromise.",
            "remediation" : "Create dedicated Admin users in IAM for administrative and daily tasks",
            "impact" : "high",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score" : "8.1",
            "pass_fail" : "INFO"
        }

        logging.info(results["name"])

        report_content = self.credential_report["Content"].decode('ascii')
        root = report_content.split("\n")[1]
        password_last_used = root.split(",")[4]
        accesskey1_last_used = root.split(",")[10]
        accesskey2_last_used = root.split(",")[15]
        results["analysis"] = "password last used: {} Access Key 1 last used: {} Access Key 2 last used: {}".format(password_last_used, accesskey1_last_used, accesskey2_last_used)
        results["affected"].append(self.account_id)

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
            "affected": [],
            "analysis" : "",
            "description" : "Password policies are, in part, used to enforce password complexity requirements. IAM password policies can be used to ensure password are at least a given length. It is recommended that the password policy require a minimum password length 14. Setting a password complexity policy increases account resiliency against brute force login attempts.",
            "remediation" : "Ensure IAM password policy requires minimum length of 14 or greater",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])
     
        if self.password_policy:
            password_length = self.password_policy["MinimumPasswordLength"]        
            results["analysis"] = "Minimum Password Length = {}".format(password_length)
            if password_length < 14:
                results["affected"].append(self.account_id)
                results["pass_fail"] = "FAIL"
            else:
                results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "No password policy configured"
            results["affected"].append(self.account_id)
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
            "affected": [],
            "analysis" : "",
            "description" : "IAM password policies can prevent the reuse of a given password by the same user. It is recommended that the password policy prevent the reuse of passwords. Preventing password reuse increases account resiliency against brute force login attempts.",
            "remediation" : "Ensure IAM password policy prevents password reuse",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])


        if self.password_policy:
            try:
                password_reuse = self.password_policy["PasswordReusePrevention"]
            except KeyError:
                results["analysis"] = "Password Reuse Prevention Not Set"
                results["affected"].append(self.account_id)
                results["pass_fail"] = "FAIL"
            else:
                results["analysis"] = "Password Reuse Prevention = {}".format(password_reuse)
                if password_reuse < 24:
                    results["affected"].append(self.account_id)
                    results["pass_fail"] = "FAIL"
                else:
                    results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional credentials. With MFA enabled, when a user signs in to the AWS Console, they will be prompted for their user name and password as well as for an authentication code from their physical or virtual MFA token. It is recommended that MFA be enabled for all accounts that have a console password. Enabling MFA provides increased security for console access as it requires the authenticating principal to possess a device that displays a time-sensitive key and have knowledge of a credential.",
            "remediation" : "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        report_content = self.credential_report["Content"].decode('ascii')

        for user in report_content.split("\n"):
            password_enabled = user.split(",")[3]
            mfa_active = user.split(",")[7]
            if password_enabled == "true":
                if mfa_active == "false":
                    results["affected"].append(user.split(",")[0])
        
        if results["affected"]:
            results["analysis"] = "The affected users do not have MFA enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All users have MFA enabled."
            results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "AWS console defaults to no check boxes selected when creating a new IAM user. When cerating the IAM User credentials you have to determine what type of access they require. Programmatic access: The IAM user might need to make API calls, use the AWS CLI, or use the Tools for Windows PowerShell. In that case, create an access key (access key ID and a secret access key) for that user. AWS Management Console access: If the user needs to access the AWS Management Console, create a password for the user. Requiring the additional steps be taken by the user for programmatic access after their profile has been created will give a stronger indication of intent that access keys are [a] necessary for their work and [b] once the access key is established on an account that the keys may be in use somewhere in the organization.",
            "remediation" : "Do not setup access keys during initial user setup",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        report_content = self.credential_report["Content"].decode('ascii')

        for user in report_content.split("\n"):
            password_enabled = user.split(",")[3]
            access_key_1_active = user.split(",")[8]
            access_key_1_last_used = user.split(",")[10]
            access_key_2_active = user.split(",")[13]
            access_key_2_last_used = user.split(",")[15]

            if password_enabled == "true":
                if access_key_1_active == "true" and access_key_1_last_used == "N/A":
                        results["affected"].append(user.split(",")[0])
                if access_key_2_active == "true" and access_key_2_last_used == "N/A":
                        results["affected"].append(user.split(",")[0])
        
        if results["affected"]:
            results["analysis"] = "The affected users have unused Access Keys."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused Access Keys found."
            results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused in 45 or greater days be deactivated or removed. Disabling or removing unnecessary credentials will reduce the window of opportunity for credentials associated with a compromised or abandoned account to be used.",
            "remediation" : "Ensure credentials unused for 45 days or greater are disabled",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        report_content = self.credential_report["Content"].decode('ascii')

        for user in report_content.split("\n"):
            password_enabled = user.split(",")[3]
            password_last_used = user.split(",")[4]
            access_key_1_active = user.split(",")[8]
            access_key_1_last_used = user.split(",")[10]
            access_key_2_active = user.split(",")[13]
            access_key_2_last_used = user.split(",")[15]

            if password_enabled == "true":
                if password_last_used != "N/A" and password_last_used != "no_information":
                    year, month, day = password_last_used.split("T")[0].split("-")
                    password_last_used_date = date(int(year), int(month), int(day))
                    if password_last_used_date < (date.today() - timedelta(days=45)):
                        results["affected"].append(user.split(",")[0])

            if access_key_1_active == "true":
                if access_key_1_last_used != "N/A":
                    year, month, day = access_key_1_last_used.split("T")[0].split("-")
                    access_key_1_last_used_date = date(int(year), int(month), int(day))
                    if access_key_1_last_used_date < (date.today() - timedelta(days=45)):
                        results["affected"].append(user.split(",")[0])
            
            if access_key_2_active == "true":
                if access_key_2_last_used != "N/A":
                    year, month, day = access_key_2_last_used.split("T")[0].split("-")
                    access_key_2_last_used_date = date(int(year), int(month), int(day))
                    if access_key_2_last_used_date < (date.today() - timedelta(days=45)):
                        results["affected"].append(user.split(",")[0])

        if results["affected"]:
            results["analysis"] = "The affected users have credentials (password or keys) not used in the last 45 days."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused credentials found."
            results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "Access keys are long-term credentials for an IAM user or the AWS account 'root' user. You can use access keys to sign programmatic requests to the AWS CLI or AWS API (directly or using the AWS SDK) Access keys are long-term credentials for an IAM user or the AWS account root user. You can use access keys to sign programmatic requests to the AWS CLI or AWS API. One of the best ways to protect your account is to not allow users to have multiple access keys.",
            "remediation" : "Ensure there is only one active access key available for any single IAM user",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        report_content = self.credential_report["Content"].decode('ascii')

        for user in report_content.split("\n"):
            access_key_1_active = user.split(",")[8]
            access_key_2_active = user.split(",")[13]

            if access_key_1_active == "true":
                if access_key_2_active == "true":
                        results["affected"].append(user.split(",")[0])

        if results["affected"]:
            results["analysis"] = "The affected users have more than one access key."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No used with more than one access key found."
            results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests that you make to AWS. AWS users need their own access keys to make programmatic calls to AWS from the AWS Command Line Interface (AWS CLI), Tools for Windows PowerShell, the AWS SDKs, or direct HTTP calls using the APIs for individual AWS services. It is recommended that all access keys be regularly rotated. Rotating access keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Access keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen.",
            "remediation" : "Ensure access keys are rotated every 90 days or less",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])

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
                        results["affected"].append(user.split(",")[0])
            
            if access_key_2_active == "true":
                if access_key_2_last_rotated != "N/A":
                    year, month, day = access_key_2_last_rotated.split("T")[0].split("-")
                    access_key_2_last_rotated_date = date(int(year), int(month), int(day))
                    if access_key_2_last_rotated_date < (date.today() - timedelta(days=90)):
                        results["affected"].append(user.split(",")[0])

        if results["affected"]:
            results["analysis"] = "The affected users have access keys that have not been rotated in the last 90 days."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No keys that have not been rotated found."
            results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "IAM users are granted access to services, functions, and data through IAM policies. There are three ways to define policies for a user: 1) Edit the user policy directly, aka an inline, or user, policy; 2) attach a policy directly to a user; 3) add the user to an IAM group that has an attached policy. Only the third implementation is recommended. Assigning IAM policy only through groups unifies permissions management to a single, flexible layer consistent with organizational functional roles. By unifying permissions management, the likelihood of excessive permissions is reduced.",
            "remediation" : "Ensure IAM Users Receive Permissions Only Through Groups",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for user in self.users:
            inline_policies = self.client.list_user_policies(UserName=user["UserName"])
            attached_policies = self.client.list_attached_user_policies(UserName=user["UserName"])

            if inline_policies["PolicyNames"]:
                results["affected"].append(user["UserName"])
            
            if attached_policies["AttachedPolicies"]:
                results["affected"].append(user["UserName"])

        if results["affected"]:
            results["analysis"] = "The affected users have managed or inline policies directly attached."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No directly attached policies found."
            results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege -that is, granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges. It's more secure to start with a minimum set of permissions and grant additional permissions as necessary, rather than starting with permissions that are too lenient and then trying to tighten them later. Providing full administrative privileges instead of restricting to the minimum set of permissions that the user is required to do exposes the resources to potentially unwanted actions. IAM policies that have a statement with Effect: Allow with Action: * over Resource: * should be removed.",
            "remediation" : "Policies that grant full administrative privileges should be removed in favour of AWS Managed policies and applied using the principle of least privilege",
            "impact" : "high",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score" : "8.1",
            "pass_fail" : "PASS"
        }

        logging.info(results["name"])

        for policy in self.customer_policies:

            arn = policy["Arn"]
            policy_name = policy["PolicyName"]
            #policy_id = policy["PolicyId"]
            version_id = policy["DefaultVersionId"]        

            statements = self.client.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"]["Document"]["Statement"]
            
            if type(statements) is not list:
                statements = [ statements ]

            for statement in statements:
                try:
                    if statement["Effect"] == "Allow":
                        if statement["Action"] == "*":
                            if statement["Resource"] == "*":
                                results["affected"].append(policy_name)
                except KeyError: # catch statements that dont have "Action" and are using "NotAction" instead
                    pass

        if results["affected"]:
            results["analysis"] = "The affected custom policies grant full *:* privileges."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No custom policies that allow full *:* privileges found."
            results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. Create an IAM Role to allow authorized users to manage incidents with AWS Support. By implementing least privilege for access control, an IAM Role will require an appropriate IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support.",
            "remediation" : "Ensure a support role has been created",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for policy in self.aws_policies:
            
            if policy["PolicyName"] == "AWSSupportAccess":

                if policy["AttachmentCount"] != 0:
                    results["analysis"] = "AWSSupportAccess Policy is attached - but not to a custom support role"
                    results["affected"].append(self.account_id)
                    results["pass_fail"] = "FAIL"
                else:
                    results["analysis"] = "AWSSupportAccess Policy is not attached to any entities"
                    results["affected"].append(self.account_id)
                    results["pass_fail"] = "FAIL"
                
                policy_roles = self.client.list_entities_for_policy(PolicyArn=policy["Arn"])["PolicyRoles"]
                
                if policy_roles:
                    results["analysis"] = "AWSSupportAccess Policy is attached to role: {}".format(" ".join(policy_roles["RoleName"]))
                    results["affected"].append(self.account_id)
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
            "affected": [],
            "analysis" : "",
            "description" : "To enable HTTPS connections to your website or application in AWS, you need an SSL/TLS server certificate. You can use ACM or IAM to store and deploy server certificates. Use IAM as a certificate manager only when you must support HTTPS connections in a region that is not supported by ACM. IAM securely encrypts your private keys and stores the encrypted version in IAM SSL certificate storage. IAM supports deploying server certificates in all regions, but you must obtain your certificate from an external provider for use with AWS. You cannot upload an ACM certificate to IAM. Additionally, you cannot manage your certificates from the IAM Console. Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be deployed accidentally to a resource such as AWS Elastic Load Balancer (ELB), which can damage the credibility of the application/website behind the ELB. As a best practice, it is recommended to delete expired certificates.",
            "remediation" : "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        server_certificates = self.client.list_server_certificates()["ServerCertificateMetadataList"]

        if not server_certificates:
            results["analysis"] = "No server certificates found"
            results["pass_fail"] = "PASS"
        
        for cert in server_certificates:
            expiration = cert["Expiration"]
            server_certificate_name = cert["ServerCertificateName"]
            expiration_date = date(expiration.year, expiration.month, expiration.day)
            if expiration_date < date.today():
                results["affected"].append(server_certificate_name)

        if results["affected"]:
            results["analysis"] = "The affected server certificates have expired."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No expired server certificates found."
            results["pass_fail"] = "PASS"

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
            "affected": [],
            "analysis" : "",
            "description" : "In multi-account environments, IAM user centralization facilitates greater user control. User access beyond the initial account is then provided via role assumption. Centralization of users can be accomplished through federation with an external identity provider or through the use of AWS Organizations. Centralizing IAM user management to a single identity store reduces complexity and thus the likelihood of access management errors.",
            "remediation" : "manage IAM user centrally and have them assume roles, configured following the priniciple of least privilege, within target accounts when requiring access",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = "Manual Check"
        results["pass_fail"] = "INFO"

        return results
    
    def iam_20(self):
        # unused groups

        results = {
            "id" : "iam_20",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "iam",
            "name" : "Unused IAM Groups",
            "affected": [],
            "analysis" : "",
            "description" : "The affected IAM groups, do not contain any users and are therefore not being used. To maintain the hygiene of the environment, make maintenance and auditing easier and reduce the risk of IAM groups erroneously being used and inadvertently granting more access than required, all old unused IAM groups should be removed.",
            "remediation" : "Ensure all IAM groups that are temporary and not being used are deleted when no longer required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["affected"] = [ group["Group"]["GroupName"] for group in self.groups if not group["Users"]]

        if results["affected"]:
            results["analysis"] = "The affected groups contain no users."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused IAM Groups found."
            results["pass_fail"] = "PASS"

        return results
    
    def iam_21(self):
        # Cross-Account AssumeRole Policy Lacks External ID

        results = {
            "id" : "iam_21",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "iam",
            "name" : "Cross-Account AssumeRole Policy Lacks External ID",
            "affected": [],
            "analysis" : "",
            "description" : 'The affected AWS account has a number of Cross-Account assume role policies which lack an external ID. Policies which lack an external ID are vulnerable to what’s known as the “Confused Deputy Problem”.\nAn assume role policy allow a trust relationship to be set up between two accounts that allows users to assume a role and inherit permissions in other accounts. This is often used to allow third party access to your account to perform specific support roles or tasks like monitoring and maintenance. When the third party requires access to your account they can assume the IAM role and its temporary security credentials without needing to configure IAM users and share long-term credentials (for example, an IAM users access key) . Configuring cross account roles with external IDs and or MFA verification can help ensure that when using the role to access resources in your account they are acting under genuine circumstances and have been “confused” or socially engineered by a malicious actor to escalate permissions within or perform malicious actions on in your AWS account. Let say Example Corp requires access to certain resources in your AWS account. But in addition to you, Example Corp has other customers and needs a way to access each customers AWS resources. Instead of asking its customers for their AWS account access keys, which are secrets that should never be shared, Example Corp requests a role ARN from each customer. But another Example Corp customer might be able to guess or obtain your role ARN. That customer could then use your role ARN to gain access to your AWS resources by way of Example Corp. This form of permission escalation is known as the confused deputy problem. The external ID is a piece of data that can be passed to the AssumeRole API of the Security Token Service (STS). You can then use the external ID in the condition element in a role’s trust policy, allowing the role to be assumed only when a certain value is present in the external ID.',
            "remediation" : 'All Cross-Account roles which provide a level of privileged access should be configured with a unique and complex external ID as well as performing re authentication via MFA.\nMore Information\nhttps://aws.amazon.com/blogs/security/how-to-use-external-id-when-granting-access-to-your-aws-resources/\nhttps://en.wikipedia.org/wiki/Confused_deputy_problem',
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L",
            "cvss_score" : "5.5",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        affected_statements = {}

        for role in self.roles:
            for statement in role["AssumeRolePolicyDocument"]["Statement"]:
                if statement["Effect"] == "Allow":
                    if "AWS" in statement["Principal"]:
                        if statement["Action"] == "sts:AssumeRole":
                            try:
                                if not re.match(".*ExternalId.*", str(statement["Condition"])):
                                    results["affected"].append(role["RoleName"])
                                    affected_statements[role["RoleName"]] = statement
                            except KeyError: # no conditions defined
                                results["affected"].append(role["RoleName"])
                                affected_statements[role["RoleName"]] = statement


        if results["affected"]:
            results["analysis"] = "The affected cross account roles do not have an external ID configured.\nAffected Roles and Statements:\n{}".format(json.dumps(affected_statements))
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing roles found."
            results["pass_fail"] = "PASS"

        return results
    
    def iam_22(self):
        # Admin Groups

        results = {
            "id" : "iam_22",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "iam",
            "name" : "Groups Granting Full Admin Access",
            "affected": [],
            "analysis" : "",
            "description" : 'The affected Groups grant member user full admin "*" access to the account',
            "remediation" : 'ensure only users that require admin access have it.',
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        policies = self.customer_policies + self.aws_policies
        users = {}

        for group in self.groups:
            managed_policies = self.client.list_attached_group_policies(GroupName=group["Group"]["GroupName"])["AttachedPolicies"]
            
            for group_policy in managed_policies:
                for policy in policies:
                    arn = policy["Arn"]
                    if group_policy["PolicyArn"] == arn:
                        statements = self.client.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]["Statement"]
                        if type(statements) is not list:
                            statements = [ statements ]

                        for statement in statements:
                            try:
                                if statement["Effect"] == "Allow":
                                    if statement["Action"] == "*":
                                        if statement["Resource"] == "*":
                                            results["affected"].append(group["Group"]["GroupName"])
                                            users[group["Group"]["GroupName"]] = [ user["UserName"] for user in group["Users"] ]
                            except KeyError: # catch statements that dont have "Action" and are using "NotAction" instead
                                pass
            
            
            inline_policies = self.client.list_group_policies(GroupName=group["Group"]["GroupName"])["PolicyNames"]

            for policy_name in inline_policies:
                statements = self.client.get_group_policy(GroupName=group["Group"]["GroupName"], PolicyName=policy_name)["PolicyDocument"]["Statement"]
                if type(statements) is not list:
                    statements = [ statements ]

                for statement in statements:
                    try:
                        if statement["Effect"] == "Allow":
                            if statement["Action"] == "*":
                                if statement["Resource"] == "*":
                                    results["affected"].append(group["Group"]["GroupName"])
                                    users[group["Group"]["GroupName"]] = [ user["UserName"] for user in group["Users"] ]
                    except KeyError: # catch statements that dont have "Action" and are using "NotAction" instead
                        pass

        if results["affected"]:
            results["analysis"] = "The affected groups grant admin access.\nAffected Groups and Users:\n{}".format(json.dumps(users))
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No Admin Groups Found."
            results["pass_fail"] = "PASS"

        return results
    
    def iam_23(self):
        # Group Name does not Indicate Admin Access

        results = {
            "id" : "iam_23",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "iam",
            "name" : "Group Name does not Indicate Admin Access",
            "affected": [],
            "analysis" : "",
            "description" : 'An AWS principle was found that grants admin privileges within the AWS account. The name of this group does not clearly indicate the level of privilege provided. To make maintaining the account as easy as possible and to reduce the risk of administrative privileges being granted to AWS principles that do not require them by mistake it is recommended to implement a common naming convention for all custom groups, roles and policies which indicates the level of access being granted. ',
            "remediation" : 'Implement a simple naming convention for all custom groups, roles and policies which clearly indicates what permissions they grant and who they should apply to.',
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        policies = self.customer_policies + self.aws_policies
        users = {}

        for group in self.groups:
            managed_policies = self.client.list_attached_group_policies(GroupName=group["Group"]["GroupName"])["AttachedPolicies"]
            
            for group_policy in managed_policies:
                for policy in policies:
                    arn = policy["Arn"]
                    if group_policy["PolicyArn"] == arn:
                        statements = self.client.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]["Statement"]
                        if type(statements) is not list:
                            statements = [ statements ]

                        for statement in statements:
                            try:
                                if statement["Effect"] == "Allow":
                                    if statement["Action"] == "*":
                                        if statement["Resource"] == "*":
                                            if not re.match(".*[Aa][Dd][Mm][Ii][Nn].*", group["Group"]["GroupName"]):
                                                results["affected"].append(group["Group"]["GroupName"])
                                                users[group["Group"]["GroupName"]] = [ user["UserName"] for user in group["Users"] ]
                            except KeyError: # catch statements that dont have "Action" and are using "NotAction" instead
                                pass
            
            
            inline_policies = self.client.list_group_policies(GroupName=group["Group"]["GroupName"])["PolicyNames"]

            for policy_name in inline_policies:
                statements = self.client.get_group_policy(GroupName=group["Group"]["GroupName"], PolicyName=policy_name)["PolicyDocument"]["Statement"]
                if type(statements) is not list:
                    statements = [ statements ]

                for statement in statements:
                    try:
                        if statement["Effect"] == "Allow":
                            if statement["Action"] == "*":
                                if statement["Resource"] == "*":
                                    if not re.match(".*[Aa][Dd][Mm][Ii][Nn].*", group["Group"]["GroupName"]):
                                        results["affected"].append(group["Group"]["GroupName"])
                                        users[group["Group"]["GroupName"]] = [ user["UserName"] for user in group["Users"] ]
                    except KeyError: # catch statements that dont have "Action" and are using "NotAction" instead
                        pass

        if results["affected"]:
            results["analysis"] = "The affected groups grant admin access which is not indicated by their name.\nAffected Groups and Users:\n{}".format(json.dumps(users))
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No Admin Groups Found."
            results["pass_fail"] = "PASS"

        return results
