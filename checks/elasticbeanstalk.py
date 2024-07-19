import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class elasticbeanstalk(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.environments = self.get_environments()
        self.configuration_settings = self.get_configuration_settings()
        #self.applications = self.get_applications()

    def run(self):
        findings = []
        findings += [ self.elasticbeanstalk_1() ]
        findings += [ self.elasticbeanstalk_2() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.elasticbeanstalk_1() ]
        findings += [ self.elasticbeanstalk_2() ]
        return findings

    def get_environments(self):
        environments = {}
        logging.info("getting environments")
        for region in self.regions:
            client = self.session.client('elasticbeanstalk', region_name=region)
            try:
                results = client.describe_environments()["Environments"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting environments - %s" % e.response["Error"]["Code"])
            else:
                if results:
                    environments[region] = results
        return environments
    
    def get_applications(self):
        applications = {}
        logging.info("getting applications")
        for region in self.regions:
            client = self.session.client('elasticbeanstalk', region_name=region)
            try:
                results = client.describe_applications()["Applications"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting applications - %s" % e.response["Error"]["Code"])
            else:
                if results:
                    applications[region] = results
        return applications

    def get_configuration_settings(self):
        configuration_settings = {}
        logging.info("getting configuration_settings")
        for region, environments in self.environments.items():
            configuration_settings[region] = {}
            client = self.session.client('elasticbeanstalk', region_name=region)
            for environment in environments:
                try:
                    results = client.describe_configuration_settings(EnvironmentName=environment["EnvironmentName"], ApplicationName=environment["ApplicationName"])["ConfigurationSettings"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting environment configuration settings - %s" % e.response["Error"]["Code"])
                else:
                    if results:
                        configuration_settings[region][environment["EnvironmentName"]] = results
        return configuration_settings

    def elasticbeanstalk_1(self):
        # Ensure Managed Platform updates is configured (CIS)

        results = {
            "id" : "elasticbeanstalk_1",
            "ref" : "6.1",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "elasticbeanstalk",
            "name" : "Ensure Managed Platform updates is configured (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "AWS Elastic Beanstalk regularly releases platform updates to provide fixes, software updates, and new features. With managed platform updates, you can configure your environment to automatically upgrade to the latest version of a platform during a scheduled maintenance window. Your application remains in service during the update process with no reduction in capacity. Managed updates are available on both single-instance and load-balanced environments. They also ensure you aren't introducing any vulnerabilities by running legacy systems that require updates and patches.",
            "remediation" : "From the Console:\n1. Login to AWS Console using https://console.aws.amazon.com/elasticbeanstalk\n2. On the left hand side click Environments\n3. Click on the Environment name that you want to update\n4. Under the environment_name-env in the left column click Configuration\n5. Scroll down under Configurations\n6. Under category look for Managed updates\n7. Click on Edit\n8. On the Managed Platform Updates page\nManaged updates - click the Enable checkbox\nWeekly update window - set preferred maintenance window\nUpdate level- set it to Minor and patch\nInstance replacement - click the Enabled checkbox\n9. Click Apply\n10. Repeat steps 3-8 for each environment within the current region that needs Managed updates set.\n11. Then repeat the remediation process for all other regions identified in the Audit",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, environments in self.configuration_settings.items():
            for environment, configuration_settings in environments.items():
                for setting in configuration_settings:
                    for option in setting["OptionSettings"]:
                        if option["OptionName"] == "ManagedActionsEnabled":
                            if option["Value"] != "true":
                                results["affected"].append(environment)

        if results["affected"]:
            results["analysis"] = "The affected envionments do not have managed updates enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = ""
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def elasticbeanstalk_2(self):
        # Ensure Persistent logs is setup and configured to S3 (CIS)

        results = {
            "id" : "elasticbeanstalk_2",
            "ref" : "6.2",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "elasticbeanstalk",
            "name" : "Ensure Persistent logs is setup and configured to S3 (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Elastic Beanstalk can be configured to automatically stream logs to the CloudWatch service. With CloudWatch Logs, you can monitor and archive your Elastic Beanstalk application, system, and custom log files from Amazon EC2 instances of your environments.",
            "remediation" : "From the Console:\n1. Login to AWS Console using https://console.aws.amazon.com/elasticbeanstalk\n2. On the left hand side click Environments\n3. Click on the Environment name that you want to update\n4. Under the environment_name-env in the left column click Configuration\n5. Scroll down under Configurations\n6. Under category look for Software\n7. Click on Edit\n8. On the Modify software page\nInstance log streaming to CloudWatch Logs\nLog streaming - click the Enabled checkbox\nSet the required retention based on Organization requirements\nLifecycle - Keep logs after terminating environment\n9. Click Apply\n10. Repeat steps 3-8 for each environment within the current region that needs Managed updates set",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, environments in self.configuration_settings.items():
            for environment, configuration_settings in environments.items():
                for setting in configuration_settings:
                    for option in setting["OptionSettings"]:
                        if option["OptionName"] == "StreamLogs":
                            if option["Value"] != "true":
                                results["affected"].append(environment)

        if results["affected"]:
            results["analysis"] = "The affected envionments do not have log streaming enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = ""
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
