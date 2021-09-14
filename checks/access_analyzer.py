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
            "description" : "Enable IAM Access analyzer for IAM policies about all resources in each region. IAM Access Analyzer is a technology introduced at AWS reinvent 2019. After the Analyzer is enabled in IAM, scan results are displayed on the console showing the accessible resources. Scans show resources that other accounts and federated users can access, such as KMS keys and IAM roles. So the results allow you to determine if an unintended user is allowed, making it easier for administrators to monitor least privileges access. Access Analyzer analyzes only policies that are applied to resources in the same AWS Region. AWS IAM Access Analyzer helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity. This lets you identify unintended access to your resources and data. Access Analyzer identifies resources that are shared with external principals by using logic-based reasoning to analyze the resource-based policies in your AWS environment. IAM Access Analyzer continuously monitors all policies for S3 bucket, IAM roles, KMS(Key Management Service) keys, AWS Lambda functions, and Amazon SQS(Simple Queue Service) queues.",
            "remediation" : "Enable Access Analyzer in all regions",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
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
                results["affected"] = ", ".join(self.regions)
            else:
                results["analysis"] = "the following regions do not have Access Analyzer enabled: {}".format(" ".join(failing_regions))
                results["affected"] = ", ".join(failing_regions)

        return results