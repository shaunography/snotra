import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import datetime, timezone
from datetime import timedelta

class secretsmanager(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.secrets = self.get_secrets()

    def run(self):
        findings = []
        findings += [ self.secretsmanager_1() ]
        findings += [ self.secretsmanager_2() ]
        findings += [ self.secretsmanager_3() ]
        findings += [ self.secretsmanager_4() ]
        findings += [ self.secretsmanager_5() ]
        findings += [ self.secretsmanager_6() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.secretsmanager_1() ]
        return findings

    def get_secrets(self):
        secrets = {}
        logging.info("getting secrets")
        for region in self.regions:
            client = self.session.client('secretsmanager', region_name=region)
            try:
                results = client.list_secrets()["SecretList"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting secrets - %s" % e.response["Error"]["Code"])
            else:
                if results:
                    secrets[region] = results
        return secrets

    def secretsmanager_1(self):
        # Ensure AWS Secrets manager is configured and being used by Lambda for databases (CIS)

        results = {
            "id" : "secretsmanager_1",
            "ref" : "4.3",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "secretsmanager",
            "name" : "Ensure AWS Secrets manager is configured and being used by Lambda for databases (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Lambda functions often have to access a database or other services within your environment. Credentials used to access databases and other AWS Services need to be managed and regularly rotated to keep access into critical systems secure. Keeping any credentials and manually updating the passwords would be cumbersome, but AWS Secrets Manager allows you to manage and rotate passwords. note - Lambda code should be checked for correct configuration to get the credentials from AWS Secrets Manager. This audit and remediation is only to confirm you have the credentials in Secrets manager.",
            "remediation" : "From the Console:\n1. Login to AWS Console using https://console.aws.amazon.com\n2. Click All services, click Secrets Manager under Security, Identity and Compliance.\n3. Click on Secrets.\n4. Click on Store a new secret\n5. Select the Secret type\n6. Enter the information",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.secrets:
            results["analysis"] = "Secrets Manager not in use"
            results["affected"].append(self.account_id)
        else:
            results["pass_fail"] = "INFO"
            for region, secrets in self.secrets.items():
                for secret in secrets:
                    results["affected"].append(secret["Name"])
                    results["analysis"] = "Manual Check: Check Secrets and Lambdas to see if secrets are being managed in secrets manager"

        return results

    def secretsmanager_2(self):
        # Secrets Manager secrets should have automatic rotation enabled

        results = {
            "id" : "secretsmanager_2",
            "ref" : "SecretsManager.1",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "secretsmanager",
            "name" : "Secrets Manager secrets should have automatic rotation enabled",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether a secret stored in AWS Secrets Manager is configured with automatic rotation. The control fails if the secret isn't configured with automatic rotation. If you provide a custom value for the maximumAllowedRotationFrequency parameter, the control passes only if the secret is automatically rotated within the specified window of time. Secrets Manager helps you improve the security posture of your organization. Secrets include database credentials, passwords, and third-party API keys. You can use Secrets Manager to store secrets centrally, encrypt secrets automatically, control access to secrets, and rotate secrets safely and automatically. Secrets Manager can rotate secrets. You can use rotation to replace long-term secrets with short-term ones. Rotating your secrets limits how long an unauthorized user can use a compromised secret. For this reason, you should rotate your secrets frequently. To learn more about rotation, see Rotating your AWS Secrets Manager secrets in the AWS Secrets Manager User Guide.",
            "remediation" : "To turn on automatic rotation for Secrets Manager secrets, see Set up automatic rotation for AWS Secrets Manager secrets using the console in the AWS Secrets Manager User Guide. You must choose and configure an AWS Lambda function for rotation.\nMore Information\nhttps://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_turn-on-for-other.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.secrets:
            results["analysis"] = "Secrets Manager not in use"
            results["affected"].append(self.account_id)
        else:
            for region, secrets in self.secrets.items():
                for secret in secrets:
                    try:
                        if secret["RotationEnabled"] == False:
                            results["affected"].append(secret["Name"])
                            results["pass_fail"] = "FAIL"
                            results["analysis"] = "The affected Secrets do not have rotation enabled"
                    except KeyError:
                        results["affected"].append(secret["Name"])
                        results["pass_fail"] = "FAIL"
                        results["analysis"] = "The affected Secrets do not have rotation enabled"

        return results

    def secretsmanager_3(self):
        # Secrets Manager secrets configured with automatic rotation should rotate successfully

        results = {
            "id" : "secretsmanager_3",
            "ref" : "SecretsManager.2",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "secretsmanager",
            "name" : "Secrets Manager secrets configured with automatic rotation should rotate successfully",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an AWS Secrets Manager secret rotated successfully based on the rotation schedule. The control fails if RotationOccurringAsScheduled is false. The control only evaluates secrets that have rotation turned on. Secrets Manager helps you improve the security posture of your organization. Secrets include database credentials, passwords, and third-party API keys. You can use Secrets Manager to store secrets centrally, encrypt secrets automatically, control access to secrets, and rotate secrets safely and automatically. Secrets Manager can rotate secrets. You can use rotation to replace long-term secrets with short-term ones. Rotating your secrets limits how long an unauthorized user can use a compromised secret. For this reason, you should rotate your secrets frequently. In addition to configuring secrets to rotate automatically, you should ensure that those secrets rotate successfully based on the rotation schedule. To learn more about rotation, see Rotating your AWS Secrets Manager secrets in the AWS Secrets Manager User Guide.",
            "remediation" : "If the automatic rotation fails, then Secrets Manager might have encountered errors with the configuration. To rotate secrets in Secrets Manager, you use a Lambda function that defines how to interact with the database or service that owns the secret. For help diagnosing and fixing common errors related to secrets rotation, see Troubleshooting AWS Secrets Manager rotation of secrets in the AWS Secrets Manager User Guide.\nMore Information\nhttps://docs.aws.amazon.com/secretsmanager/latest/userguide/troubleshoot_rotation.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.secrets:
            results["analysis"] = "Secrets Manager not in use"
            results["affected"].append(self.account_id)
        else:
            for region, secrets in self.secrets.items():
                for secret in secrets:
                    try:
                        if secret["NextRotationDate"] > datetime.now(timezone.utc):
                            results["affected"].append(secret["Name"])
                            results["pass_fail"] = "FAIL"
                            results["analysis"] = "The affected secrets have not been rotated"
                    except KeyError:
                        pass

        return results

    def secretsmanager_4(self):
        # Remove unused Secrets Manager secrets

        results = {
            "id" : "secretsmanager_4",
            "ref" : "SecretsManager.3",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "secretsmanager",
            "name" : "Remove unused Secrets Manager secrets",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an AWS Secrets Manager secret has been accessed within the specified time frame. The control fails if a secret is unused beyond the specified time frame. Unless you provide a custom parameter value for the access period, Security Hub uses a default value of 90 days. Deleting unused secrets is as important as rotating secrets. Unused secrets can be abused by their former users, who no longer need access to these secrets. Also, as more users get access to a secret, someone might have mishandled and leaked it to an unauthorized entity, which increases the risk of abuse. Deleting unused secrets helps revoke secret access from users who no longer need it. It also helps to reduce the cost of using Secrets Manager. Therefore, it is essential to routinely delete unused secrets.",
            "remediation" : "To delete inactive Secrets Manager secrets, see Delete an AWS Secrets Manager secret in the AWS Secrets Manager User Guide.\nMore Information\nhttps://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_delete-secret.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.secrets:
            results["analysis"] = "Secrets Manager not in use"
            results["affected"].append(self.account_id)
        else:
            for region, secrets in self.secrets.items():
                for secret in secrets:
                    try:
                        if secret["LastAccessedDate"] > (datetime.now(timezone.utc) - timedelta(days=90)):
                            results["affected"].append(secret["Name"])
                            results["pass_fail"] = "FAIL"
                            results["analysis"] = "The affected secrets has not been accessed in 90 days"
                    except KeyError:
                        logging.error(f'Error getting last accessed date for secret { secret["Name"] } - { e.response["Error"]["Code"] }')

        return results

    def secretsmanager_5(self):
        # Secrets Manager secrets should be rotated within a specified number of days

        results = {
            "id" : "secretsmanager_5",
            "ref" : "SecretsManager.4",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "secretsmanager",
            "name" : "Secrets Manager secrets should be rotated within a specified number of days",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an AWS Secrets Manager secret is rotated at least once within the specified time frame. The control fails if a secret isn't rotated at least this frequently. Unless you provide a custom parameter value for the rotation period, Security Hub uses a default value of 90 days. Rotating secrets can help you to reduce the risk of an unauthorized use of your secrets in your AWS account. Examples include database credentials, passwords, third-party API keys, and even arbitrary text. If you do not change your secrets for a long period of time, the secrets are more likely to be compromised. As more users get access to a secret, it can become more likely that someone mishandled and leaked it to an unauthorized entity. Secrets can be leaked through logs and cache data. They can be shared for debugging purposes and not changed or revoked once the debugging completes. For all these reasons, secrets should be rotated frequently. You can configure automatic rotation for secrets in AWS Secrets Manager. With automatic rotation, you can replace long-term secrets with short-term ones, significantly reducing the risk of compromise. We recommend that you configure automatic rotation for your Secrets Manager secrets. For more information, see Rotating your AWS Secrets Manager secrets in the AWS Secrets Manager User Guide. ",
            "remediation" : "To turn on automatic rotation for Secrets Manager secrets, see Set up automatic rotation for AWS Secrets Manager secrets using the console in the AWS Secrets Manager User Guide. You must choose and configure an AWS Lambda function for rotation.\nMore Information\nhttps://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_turn-on-for-other.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.secrets:
            results["analysis"] = "Secrets Manager not in use"
            results["affected"].append(self.account_id)
        else:
            for region, secrets in self.secrets.items():
                for secret in secrets:
                    try:
                        if secret["LastRotatedDate"] > (datetime.now(timezone.utc) - timedelta(days=90)):
                            results["affected"].append(secret["Name"])
                            results["pass_fail"] = "FAIL"
                            results["analysis"] = "The affected secrets has not been rotated in 90 days"
                    except KeyError:
                        pass

        return results

    def secretsmanager_6(self):
        # Secrets Manager secrets should be tagged

        results = {
            "id" : "secretsmanager_6",
            "ref" : "SecretsManager.5",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "secretsmanager",
            "name" : "Secrets Manager secrets should be tagged",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an AWS Secrets Manager secret has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the secret doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the secret isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag. For more information, see What is ABAC for AWS? in the IAM User Guide.",
            "remediation" : "To add tags to a Secrets Manager secret, see Tag AWS Secrets Manager secrets in the AWS Secrets Manager User Guide.\nMore Information\nhttps://docs.aws.amazon.com/secretsmanager/latest/userguide/managing-secrets_tagging.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.secrets:
            results["analysis"] = "Secrets Manager not in use"
            results["affected"].append(self.account_id)
        else:
            for region, secrets in self.secrets.items():
                for secret in secrets:
                    try:
                        if not secret["Tags"]:
                            results["affected"].append(secret["Name"])
                            results["pass_fail"] = "FAIL"
                            results["analysis"] = "The affected secrets do not have any tags applied"
                    except KeyError:
                        results["affected"].append(secret["Name"])
                        results["pass_fail"] = "FAIL"
                        results["analysis"] = "The affected secrets do not have any tags applied"

        return results
