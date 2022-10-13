import boto3
import logging

from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class route53(object):

    def __init__(self, session):
        self.session = session
        self.account_id = get_account_id(session)
        self.domains = self.get_domains()
        

    def run(self):
        findings = []
        findings += [ self.route53_1() ]
        findings += [ self.route53_2() ]
        return findings

    def get_domains(self):
        domains = {}
        logging.info("getting domains")
        client = self.session.client('route53domains', region_name="us-east-1")
        try:
            domains = client.list_domains()["Domains"]
        except boto3.exceptions.botocore.exceptions.ClientError as e:
            logging.error("Error getting domains - %s" % e.response["Error"]["Code"])
        return domains
    
    def route53_1(self):
        # Domain Does Not Have Domain Transfer Lock Set

        results = {
            "id" : "route53_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "route53",
            "name" : "Domain Does Not Have Domain Transfer Lock Set",
            "affected": [],
            "analysis" : "",
            "description" : "The AWS account under review contains Route53 domains that do not have Transfer Lock enabled. To avoid having a domain maliciously or erroneously transferred to a third-party, all domains should enable the transfer lock unless actively being transferred. The domain registries for all generic TLDs and many geographic TLDs let you lock a domain to prevent someone from transferring the domain to another registrar without your permission. To determine whether the registry for your domain lets you lock the domain, see Domains That You Can Register with Amazon Route 53.",
            "remediation" : "if locking is supported and you want to lock your domain, perform the following procedure. Sign in to the AWS Management Console and open the Route 53 console at https://console.aws.amazon.com/route53/. In the navigation pane, choose Registered Domains. Choose the name of the domain that you want to update. Choose Enable (to lock the domain) or Disable (to unlock the domain)., Choose Save.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for domain in self.domains:
            if domain["TransferLock"] == False:
                results["affected"].append(domain["DomainName"])


        if results["affected"]:
            results["analysis"] = "The affected domains do not have transfer lock enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing domains found"
            results["pass_fail"] = "PASS"

        return results
    
    def route53_2(self):
        # domain without auto renew enabled

        results = {
            "id" : "route53_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "route53",
            "name" : "Domain Does Not Have Auto Renew Enabled",
            "affected": [],
            "analysis" : "",
            "description" : "The AWS account under review contains Route53 domains that do not have Auto Renew enabled. To ensure you retain control of your domains and associated services including email is recommended that auto renew is enabled for all critical domains.",
            "remediation" : "",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for domain in self.domains:
            if domain["AutoRenew"] == False:
                results["affected"].append(domain["DomainName"])


        if results["affected"]:
            results["analysis"] = "The affected domains do not have auto renew enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing domains found"
            results["pass_fail"] = "PASS"

        return results
