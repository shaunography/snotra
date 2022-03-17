import boto3
import logging

from utils.utils import describe_regions

class config(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)

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

        return results