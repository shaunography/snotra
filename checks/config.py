import boto3

from utils.utils import describe_regions

class config(object):

    def __init__(self):
        self.regions = describe_regions()

    def run(self):
        findings = []
        findings += [ self.config_1() ]
        return findings
        
    def config_1(self):
        # Ensure AWS Config is enabled in all regions (Automated)

        results = {
            "id" : "config_1",
            "ref" : "3.5",
            "compliance" : "cis",
            "level" : 2,
            "service" : "config",
            "name" : "Ensure AWS Config is enabled in all regions",
            "affected": "",
            "analysis" : "AWS Config is enabled in all regions",
            "description" : "AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources. It is recommended AWS Config be enabled in all regions. The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing.",
            "remediation" : "It is recommended AWS Config be enabled in all regions.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: config_1")
        
        failing_regions = []
        
        for region in self.regions:
            client = boto3.client('config', region_name=region)
            recorder_list = client.describe_configuration_recorders()["ConfigurationRecorders"]
            if not recorder_list:
                failing_regions += [region]
            else:
                for recorder in recorder_list:
                    if recorder["recordingGroup"]["allSupported"] != True:
                        if recorder["recordingGroup"]["includeGlobalResourceTypes"] != True:
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