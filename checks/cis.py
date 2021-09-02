import boto3

from datetime import date
from datetime import timedelta

from utils.utils import credential_report
from utils.utils import password_policy

class cis:
    #def __init__(self):

    def checks(self):
        checks = [
            self.CIS1_1,
            self.CIS1_2,
            self.CIS1_3,
            self.CIS1_4,
            self.CIS1_5,
            self.CIS1_6,
            self.CIS1_7,
            self.CIS1_8,
            self.CIS1_9,
            self.CIS1_10,
            self.CIS1_11
        ]
        checks2 = [
            self.CIS1_12
        ]
        return checks2

    def CIS1_1():
        # Maintain current contact details (Manual)
        cis_dict = {
            "check" : 1.1,
            "level" : 1,
            "benchmark" : "Maintain current contact details",
            "result" : "Manual Check",
            "pass_fail" : ""
        }
        return cis_dict


    def CIS1_2():
        # Ensure security contact information is registered (Manual)
        cis_dict = {
            "check" : 1.2,
            "level" : 1,
            "benchmark" : "Ensure security contact information is registered",
            "result" : "Manual Check",
            "pass_fail" : ""
        }
        return cis_dict

    def CIS1_3():
        # Ensure security questions are registered in the AWS account
        cis_dict = {
            "check" : 1.3,
            "level" : 1,
            "benchmark" : "Ensure security questions are registered in the AWS account",
            "result" : "Manual Check",
            "pass_fail" : ""
        }
        return cis_dict

    def CIS1_4():
        # Ensure no 'root' user account access key exists (Automated)
        cis_dict = {
            "check" : 1.4,
            "level" : 1,
            "benchmark" : "Ensure no 'root' user account access key exists",
            "result" : "No root access keys exist",
            "pass_fail" : "PASS"
        }

        client = boto3.client('iam')    
        summary = client.get_account_summary()

        if summary["SummaryMap"]["AccountAccessKeysPresent"] != 0:
            cis_dict["result"] = "Root Access Keys Found"
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict

    def CIS1_5():
        # Ensure MFA is enabled for the 'root' user account (Automated)
        cis_dict = {
            "check" : 1.5,
            "level" : 1,
            "benchmark" : "Ensure MFA is enabled for the 'root' user account",
            "result" : "Root MFA is enabled",
            "pass_fail" : "PASS"
        }

        client = boto3.client('iam')    
        summary = client.get_account_summary()

        if summary["SummaryMap"]["AccountMFAEnabled"] == 0:
            cis_dict["result"] = "Root MFA Not Enabled"
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict

    def CIS1_6():
        # Ensure hardware MFA is enabled for the 'root' user account (Automated)

        cis_dict = {
            "check" : 1.6,
            "level" : 2,
            "benchmark" : "Ensure hardware MFA is enabled for the 'root' user account",
            "result" : "Root MFA is enabled (Virtual or Hardware)",
            "pass_fail" : "PASS"
        }

        client = boto3.client('iam')    
        summary = client.get_account_summary()

        if summary["SummaryMap"]["AccountMFAEnabled"] == 0:
            cis_dict["result"] = "Root MFA Disabled"
            cis_dict["pass_fail"] = "FAIL"
        
        return cis_dict


    def CIS1_7():
        # Eliminate use of the 'root' user for administrative and daily tasks (Automated)

        cis_dict = {
            "check" : 1.7,
            "level" : 1,
            "benchmark" : "Eliminate use of the 'root' user for administrative and daily tasks",
            "result" : "",
            "pass_fail" : "INFO"
        }

        report_content = credential_report()["Content"].decode('ascii')
        root = report_content.split("\n")[1]
        password_last_used = root.split(",")[4]
        accesskey1_last_used = root.split(",")[10]
        accesskey2_last_used = root.split(",")[15]
        cis_dict["result"] = "password last used: {} Access Key 1 last used: {} Access Key 2 last used: {}".format(password_last_used, accesskey1_last_used, accesskey2_last_used)

        return cis_dict

    def CIS1_8():
        # Ensure IAM password policy requires minimum length of 14 or greater (Automated)

        cis_dict = {
            "check" : 1.8,
            "level" : 1,
            "benchmark" : "Ensure IAM password policy requires minimum length of 14 or greater",
            "result" : "",
            "pass_fail" : "PASS"
        }

        password_length = password_policy()["MinimumPasswordLength"]
        if password_length < 14:
            cis_dict["result"] = "Minimum Password Length = {}".format(password_length)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS1_9():
        # Ensure IAM password policy prevents password reuse (Automated)

        cis_dict = {
            "check" : 1.9,
            "level" : 1,
            "benchmark" : "Ensure IAM password policy prevents password reuse",
            "result" : "",
            "pass_fail" : "PASS"
        }
        try:
            password_reuse = password_policy()["PasswordReusePrevention"]
        except KeyError:
            cis_dict["result"] = "Password Reuse Prevention Not Set"
            cis_dict["pass_fail"] = "FAIL"
        else:
            if password_reuse < 24:
                cis_dict["result"] = "Password Reuse Prevention = {}".format(password_reuse)
                cis_dict["pass_fail"] = "FAIL"

        return cis_dict

    def CIS1_10():
        # Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Automated)


        cis_dict = {
            "check" : 1.10,
            "level" : 1,
            "benchmark" : "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
            "result" : "",
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
            cis_dict["result"] = "The following users do not have MFA enabled: {}".format(" ".join(users))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict


    def CIS1_11():
        # Do not setup access keys during initial user setup for all IAM users that have a console password (Manual)
        
        cis_dict = {
            "check" : 1.11,
            "level" : 1,
            "benchmark" : "Do not setup access keys during initial user setup for all IAM users that have a console password",
            "result" : "",
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
            cis_dict["result"] = "The following users have unused Access Keys: {}".format(" ".join(users))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
    
    def CIS1_12():
        # Ensure credentials unused for 45 days or greater are disabled (Automated)

        cis_dict = {
            "check" : 1.12,
            "level" : 1,
            "benchmark" : "Ensure credentials unused for 45 days or greater are disabled",
            "result" : "",
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
            cis_dict["result"] = "The following users have credentials (password or keys) not used in the last 45 days: {}".format(" ".join(set(users)))
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
