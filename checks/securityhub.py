import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

class securityhub(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.security_hubs = self.get_security_hubs()

    def run(self):
        findings = []
        findings += [ self.securityhub_1() ]
        findings += [ self.securityhub_2() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.securityhub_1() ]
        return findings

    def get_security_hubs(self):
        security_hubs = {}
        logging.info("getting security hubs and enabled standards")
        for region in self.regions:
            client = self.session.client('securityhub', region_name=region)
            try:
                hub_description = client.describe_hub()
                security_hubs[region] = {}
                security_hubs[region]["HubArn"] = hub_description["HubArn"]
                security_hubs[region]["SubscribedAt"] = hub_description["SubscribedAt"]       
                try:
                    security_hubs[region]["AutoEnableControls"] = hub_description["AutoEnableControls"]
                except KeyError: # if AutoEnableControls is not returned (sometimes happens), assume it is enabled
                    security_hubs[region]["AutoEnableControls"] = True
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting security hub - %s" % e.response["Error"]["Code"])
                pass # no active subscription
            except boto3.exceptions.botocore.exceptions.SSLError as e:
                logging.error("SSL Error getting security hub - %s" % e)
            else:
                try:
                    security_hubs[region]["StandardsSubscriptions"] = client.get_enabled_standards()["StandardsSubscriptions"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting enabled standards - %s" % e.response["Error"]["Code"])
                

        return security_hubs

    def securityhub_1(self):
        # Ensure AWS Security Hub is enabled (Automated)

        results = {
            "id" : "securityhub_1",
            "ref" : "4.16",
            "compliance" : "cis",
            "level" : 2,
            "service" : "securityhub",
            "name" : "Ensure AWS Security Hub is enabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Security Hub collects security data from across AWS accounts, services, and supported third-party partner products and helps you analyze your security trends and identify the highest priority security issues. When you enable Security Hub, it begins to consume, aggregate, organize, and prioritize findings from AWS services that you have enabled, such as Amazon GuardDuty, Amazon Inspector, and Amazon Macie. You can also enable integrations with AWS partner security products. AWS Security Hub provides you with a comprehensive view of your security state in AWS and helps you check your environment against security industry standards and best practices - enabling you to quickly assess the security posture across your AWS accounts.",
            "remediation" : "Consider maintaining a Security Hub subscription to help identify security vulnerabilities within your account, ensure AWS config is enabled in all regions to allow Security hub to audit account configuration.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.security_hubs:
            results["analysis"] = "No active Security Hub subscriptions found"
            results["affected"].append(self.account_id)
            results["pass_fail"] = "FAIL"
        else:
            for region, hub in self.security_hubs.items():   
                if [ i["StandardsSubscriptionArn"] for i in hub["StandardsSubscriptions"] if i["StandardsStatus"] == "READY"]:
                    results["affected"].append(region)
                #else:
                    #incomplete_standards = [ i["StandardsSubscriptionArn"] for i in hub["StandardsSubscriptions"] if i["StandardsStatus"] == "INCOMPLETE"]
            
            if results["affected"]:
                results["analysis"] = "Security Hub Enabled with active Standards Subscripts in the affected regions."
                results["pass_fail"] = "PASS"
            else:
                results["analysis"] = "A Security hub subscription is active but no active standards subscriptions were found, ensure AWS config is enabled."
                results["affected"].append(self.account_id)
                results["pass_fail"] = "FAIL"

        return results
    
    def securityhub_2(self):
        # security hub auto enable controls disabled

        results = {
            "id" : "securityhub_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "securityhub",
            "name" : "Security Hub Auto Enable Controls",
            "affected": [],
            "analysis" : "",
            "description" : "AWS Security Hub provides you with a comprehensive view of your security state in AWS and helps you check your environment against security industry standards and best practices. Security Hub collects security data from across AWS accounts, services, and supported third-party partner products and helps you analyse your security trends and identify the highest priority security issues.",
            "remediation" : "It is recomened to auto enable new Security Hub controls as they are added to compliance standards",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.security_hubs:
            results["analysis"] = "No active Security Hub subscriptions found"
            results["affected"].append(self.account_id)
            results["pass_fail"] = "FAIL"
        else:
            results["affected"] = [ hub["HubArn"] for region, hub in self.security_hubs.items() if hub["AutoEnableControls"] == False ]
            
            if results["affected"]:
                results["analysis"] = "The affected Security Hubs do not have AutoEnableControls enabled."
                results["pass_fail"] = "FAIL"
            else:
                results["analysis"] = "All Security Hubs have AutoEnableControls enabled."
                results["pass_fail"] = "PASS"
                results["affected"].append(self.account_id)

        return results
