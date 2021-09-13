import boto3

from utils.utils import describe_regions

class guardduty(object):

    def __init__(self):
        self.regions = describe_regions()

    def run(self):
        findings = []
        findings += [ self.guardduty_1() ]
        return findings
        
    def guardduty_1(self):
        # enable guard duty in all regions
        
        results = {
            "id" : "guardduty_1",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "guardduty",
            "name" : "Enable GuardDuty in all regions",
            "affected": "",
            "analysis" : "GuardDuty is enabled in all regions",
            "description" : "GuardDuty is an AWS threat detection service that detects compromised access keys, EC2 instances, and more, allowing you to identify malicious activity and unauthorised behaviour within your account.",
            "remediation" : "Enable Guardduty in all AWS regions",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: guardduty_1")

        failing_regions = []

        for region in self.regions:
            client = boto3.client('guardduty', region_name=region)
            if not client.list_detectors()["DetectorIds"]:
                failing_regions += [region]
                
                
        if failing_regions:
            results["pass_fail"] = "FAIL"
            if set(failing_regions) == set(self.regions):
                results["analysis"] = "AWS Config is not enabled in any region"
                results["affected"] = ", ".join(self.regions)
            else:
                results["analysis"] = "the following regions do not have AWS config enabled: {}".format(" ".join(failing_regions))
                results["affected"] = ", ".join(failing_regions)
        
        return results
