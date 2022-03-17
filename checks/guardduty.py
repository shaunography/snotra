import boto3
import logging

from utils.utils import describe_regions

class guardduty(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)

    def run(self):
        findings = []
        findings += [ self.guardduty_1() ]
        return findings
        
    def guardduty_1(self):
        # enable guard duty in all regions
        
        results = {
            "id" : "guardduty_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "guardduty",
            "name" : "GuardDuty Not Enabled In All Regions",
            "affected": [],
            "analysis" : "",
            "description" : "GuardDuty is an AWS threat detection service that detects compromised access keys, EC2 instances, and more, allowing you to identify malicious activity and unauthorised behaviour within your account.",
            "remediation" : "Enable GuardDuty in all AWS regions",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region in self.regions:
            client = self.session.client('guardduty', region_name=region)
            if not client.list_detectors()["DetectorIds"]:
                results["affected"] += [region]
                
                
        if results["affected"]:
            results["pass_fail"] = "FAIL"
            if set(results["affected"]) == set(self.regions):
                results["analysis"] = "AWS GuardDuty is not enabled in any region"
            else:
                results["analysis"] = "The affected regions do not have GuardDuty enabled."
        else:
            results["analysis"] = "GuardDuty is enabled in all regions"
            results["pass_fail"] = "PASS"

        
        return results
