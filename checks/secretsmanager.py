import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
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
        # Ensure AWS Secrets manager is configured and being used by Lambda for databases (CIS)(Manual)

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
            results["analysis"] = "Secret Manager not in use"
            results["pass_fail"] = "FAIL"
        else:
            results["pass_fail"] = "INFO"
            for region, secrets in self.secrets.items():
                for secret in secrets:
                    results["analysis"].append(secret["Name"])

        return results

