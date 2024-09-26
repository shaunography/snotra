import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class batch(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.jobs = self.list_jobs()

    def run(self):
        findings = []
        findings += [ self.batch_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.batch_1() ]
        return findings

    def list_jobs(self):
        jobs = {}
        logging.info("getting jobs")
        for region in self.regions:
            client = self.session.client('batch', region_name=region)
            try:
                jobs[region] = client.list_jobs()["jobSummaryList"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting jobs - %s" % e.response["Error"]["Code"])
            except boto3.exceptions.botocore.exceptions.EndpointConnectionError:
                logging.error("Error getting jobs - EndpointConnectionError")
        return jobs
    

    def batch_1(self):
        # 

        results = {
            "id" : "batch_1",
            "ref" : "",
            "compliance" : "",
            "level" : "",
            "service" : "batch",
            "name" : "",
            "affected": [],
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if results["affected"]:
            results["analysis"] = ""
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = ""
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


