import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

class athena(object):

    def __init__(self, session):
        self.regions = describe_regions(session)
        self.session = session
        self.account_id = get_account_id(session)
        self.work_groups = self.list_work_groups()

    def run(self):
        findings = []
        findings += [ self.athena_1() ]
        return findings

    def list_work_groups(self):
        work_groups = {}
        logging.info("getting work groups")
        for region in self.regions:
            client = self.session.client('athena', region_name=region)
            try:
                work_groups[region] = client.list_work_groups()["WorkGroups"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting work groups - %s" % e.response["Error"]["Code"])
            except boto3.exceptions.botocore.exceptions.EndpointConnectionError:
                logging.error("Error getting work groups - EndpointConnectionError")
        return work_groups


    def athena_1(self):
        # Ensure that encryption at rest is enabled for Amazon Athena query results stored in Amazon S3

        results = {
            "id" : "athena_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "athena",
            "name" : "Ensure that encryption at rest is enabled for Amazon Athena query results stored in Amazon S3",
            "affected": [],
            "analysis" : "",
            "description" : "Ensure that encryption at rest is enabled for Amazon Athena query results stored in Amazon S3 in order to secure data and meet compliance requirements for data-at-rest encryption. If not enabled sensitive information at rest is not protected.",
            "remediation" : "Enable Encryption for the affected Work Groups",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, work_groups in self.work_groups.items():
            client = self.session.client('athena', region_name=region)
            try:

                for group in work_groups:
                    if group["Name"] == "primary":
                        pass
                    else:
                        work_group = client.get_work_group(WorkGroup=group["Name"])["WorkGroup"]
                        try:
                            if not work_group["Configuration"]["ResultConfiguration"]:
                                results["affected"].append("{}({})".format(work_group["Name"], region))
                        except KeyError:
                            logging.error("Error getting encryption configuration - %s" % e.response["Error"]["Code"])

            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting work group - %s" % e.response["Error"]["Code"])
            except boto3.exceptions.botocore.exceptions.EndpointConnectionError:
                logging.error("Error getting work groups - EndpointConnectionError")

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No Athena Work Groups found that do not utilise encryption"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
