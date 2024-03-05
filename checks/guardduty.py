import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

class guardduty(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.guardduty_1() ]
        findings += [ self.guardduty_2() ]
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
            try:
                if not client.list_detectors()["DetectorIds"]:
                    results["affected"] += [region]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting detectors - %s" % e.response["Error"]["Code"])
                
                
        if results["affected"]:
            results["pass_fail"] = "FAIL"
            if set(results["affected"]) == set(self.regions):
                results["analysis"] = "AWS GuardDuty is not enabled in any region"
            else:
                results["analysis"] = "The affected regions do not have GuardDuty enabled."
        else:
            results["analysis"] = "GuardDuty is enabled in all regions"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results

    def guardduty_2(self):
        # Guard duty Findings High
        
        results = {
            "id" : "guardduty_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "guardduty",
            "name" : "High Risk GuardDuty findings",
            "affected": [],
            "analysis" : "",
            "description" : "High Risk Guardduty findings have been found within your AWS account. GuardDuty is an AWS threat detection service that detects compromised access keys, EC2 instances, and more, allowing you to identify malicious activity and unauthorised behaviour within your account.",
            "remediation" : "Review all outstanding Guardduty findins and investigate, respond and remediate as required. It is reccomended to review findings on a regular basis.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        high_findings = {}
        
        for region in self.regions:
            client = self.session.client('guardduty', region_name=region)
            try:
                detector_ids = client.list_detectors()["DetectorIds"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting detectors - %s" % e.response["Error"]["Code"])
            else:
                for detector_id in detector_ids:
                    high_findings["{}({})".format(detector_id, region)] = []
                    try:
                        findings_ids = client.list_findings(DetectorId=detector_id)["FindingIds"]
                        findings = client.get_findings(DetectorId=detector_id, FindingIds=findings_ids)["Findings"]
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting keys - %s" % e.response["Error"]["Code"])
                    else:
                        for finding in findings:
                            if finding["Severity"] == 8: # Severity LOW=2, MED=4, HIGH=8
                                if finding["Service"]["Archived"] == False:
                                    if "{}({})".format(detector_id, region) not in results["affected"]:
                                        results["affected"].append("{}({})".format(detector_id, region))
                                    high_findings["{}({})".format(detector_id, region)].append(finding["Title"])
                
                
        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = high_findings
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        
        return results
