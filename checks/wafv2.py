import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

class wafv2(object):

    def __init__(self, session):
        self.regions = describe_regions(session)
        self.session = session
        self.account_id = get_account_id(session)
        self.web_acls = self.get_web_acls()

    def run(self):
        findings = []
        findings += [ self.wafv2() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def get_web_acls(self):
        acls = {}
        logging.info("getting web acls")
        for region in self.regions:
            client = self.session.client('wafv2', region_name=region)
            try:
                items = client.list_web_acls(Scope="REGIONAL")["WebACLs"]
                #items = client.list_web_acls(Scope="CLOUDFRONT")["WebACLs"]
                if items:
                    acls[region] = items
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting web acls - %s" % e.response["Error"]["Code"])
        return acls


    def wafv2(self):
        # WAFv2 Web ACLs Without Logging Enabled

        results = {
            "id" : "wafv2_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "wafv2",
            "name" : "WAFv2 Web ACLs Without Logging Enabled",
            "affected": [],
            "analysis" : "",
            "description" : "WAFv2 Web ACLs do not have logging enabled. Logging is an important part of maintaining the reliability, availability, and performance of AWS WAF globally. It is a business and compliance requirement in many organizations, and allows you to troubleshoot application behavior. It also provides detailed information about the traffic that is analyzed by the web ACL that is attached to AWS WAF.",
            "remediation" : "Enable logging on the affected Web ACLs.\nMore Information\nhttps://docs.aws.amazon.com/waf/latest/APIReference/API_LoggingConfiguration.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, acls in self.web_acls.items():
            client = self.session.client('wafv2', region_name=region)
            for acl in acls:
                try:
                    logging.info("getting logging configuration")
                    logging_configuration = client.get_logging_configuration(ResourceArn=acl["ARN"])["LoggingConfiguration"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting web acls - %s" % e.response["Error"]["Code"])
                    if e.response["Error"]["Code"] == "WAFNonexistentItemException":
                        results["affected"].append(acl["Name"])

        if results["affected"]:
            results["analysis"] = "The affected WAFv2 Web Acls do not have logging enabled."
            results["pass_fail"] = "FAIL"
        elif self.web_acls:
            results["analysis"] = "All Web ACLs have logging enabled"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "No Web ACLs found"

        return results

