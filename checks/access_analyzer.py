import boto3

from utils.utils import describe_regions

class access_analyzer(object):

    def __init__(self):
        self.regions = describe_regions()

    def run(self):
        findings = []
        findings += [ self.access_analyzer_1() ]
        return findings

    def access_analyzer_1(self):
        # Ensure that IAM Access analyzer is enabled for all regions (Automated)

        results = {
            "id" : "access_analyzer_1",
            "ref" : "1.20",
            "compliance" : "cis",
            "level" : 1,
            "service" : "access_analyzer",
            "name" : "Ensure that IAM Access analyzer is enabled for all regions",
            "affected": "",
            "analysis" : "Access Analyzer is enabled in all regions",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        print("running check: access_analyzer_1")

        failing_regions = []

        for region in self.regions:
            client = boto3.client('accessanalyzer', region_name=region)
            if not client.list_analyzers()["analyzers"]:
                failing_regions += [region]

        if failing_regions:
            results["pass_fail"] = "FAIL"

            if set(failing_regions) == set(self.regions):
                results["analysis"] = "Access Analyzer is not enabled in any region"
            else:
                results["analysis"] = "the following regions do not have Access Analyzer enabled: {}".format(" ".join(failing_regions))

        return results