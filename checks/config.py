import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

class config(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.conformance_packs = self.get_conformance_packs()

    def run(self):
        findings = []
        findings += [ self.config_1() ]
        findings += [ self.config_2() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.config_1() ]
        findings += [ self.config_2() ]
        return findings

    def get_conformance_packs(self):
        conformance_packs = {}
        logging.info("getting conformance packs")
        for region in self.regions:
            client = self.session.client('config', region_name=region)
            try:
                packs = client.describe_conformance_packs()["ConformancePackDetails"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting conformance packs - %s" % e.response["Error"]["Code"])
            else:
                if packs:
                    conformance_packs[region] = packs
        return conformance_packs
        
    def config_1(self):
        # Ensure AWS Config is enabled in all regions (Automated)

        results = {
            "id" : "config_1",
            "ref" : "3.3",
            "compliance" : "cis",
            "level" : 2,
            "service" : "config",
            "name" : "Ensure AWS Config is enabled in all regions (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources. It is recommended AWS Config be enabled in all regions. The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing.",
            "remediation" : "It is recommended AWS Config be enabled in all regions.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region in self.regions:
            client = self.session.client('config', region_name=region)
            try:
                recorder_list = client.describe_configuration_recorders()["ConfigurationRecorders"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting configuration recorders - %s" % e.response["Error"]["Code"])
            else:
                if not recorder_list:
                    results["affected"].append(region)
                else:
                    for recorder in recorder_list:
                        if recorder["recordingGroup"]["allSupported"] != True:
                            if recorder["recordingGroup"]["includeGlobalResourceTypes"] != True:
                                results["affected"].append(region)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            if set(results["affected"]) == set(self.regions):
                results["analysis"] = "AWS Config is not enabled in any region"
            else:
                results["analysis"] = "The affected regions do not have AWS config enabled."
        else:
            results["analysis"] = "AWS Config is enabled in all regions."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def config_2(self):
        # Ensure AWS Config is Enabled for Lambda and Serverless (CIS)

        results = {
            "id" : "config_2",
            "ref" : "4.1",
            "compliance" : "cis_compute",
            "level" : 2,
            "service" : "config",
            "name" : "Ensure AWS Config is Enabled for Lambda and Serverless (CIS)(Manual)",
            "affected": [],
            "analysis" : "",
            "description" : "With AWS Config, you can track configuration changes to the Lambda functions (including deleted functions), runtime environments, tags, handler name, code size, memory allocation, timeout settings, and concurrency settings, along with Lambda IAM execution role, subnet, and security group associations. This gives you a holistic view of the Lambda function’s lifecycle and enables you to surface that data for potential audit and compliance requirements.",
            "remediation" : "From the Console:\n1. Login to AWS Console using https://console.aws.amazon.com\n2. Click All services, click Config under Management & Governance.\n3. This will open up the Config dashboard.\n4. Click Conformance packs\n5. Click on Deploy conformance pack\n6. Click on Use sample template\n7. Click the down arrow under Sample template\n8. Scroll down and click on Operational Best Practices for Serverless\n9. Click Next\n10. Give it a Conformance pack name Serverless.\n11. Click Next\n12. Click Deploy conformance pack\n13. Click on Deploy conformance pack\n14. Click on Use sample template\n15. Click the down arrow under Sample template\n16. Scroll down and click on Security Best Practices for Lambda\n17. Click Next\n18. Give it a Conformance pack name LambaSecurity.\n19. Click Next\n20. Click Deploy conformance pack\n21. Repeat steps 2-20 for all regions used.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        if not self.conformance_packs:
            results["affected"].append(self.account_id)
            results["analysis"] = "No conformance packs in use"
            results["pass_fail"] = "FAIL"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = self.conformance_packs
            results["pass_fail"] = "INFO"

        return results
