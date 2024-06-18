import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class resourcegroupstaggingapi(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.tag_keys = self.get_tag_keys()
        self.tag_values = self.get_tag_values()
        self.all_resources = self.get_all_resources()

    def run(self):
        findings = []
        findings += [ self.resourcegroupstaggingapi_1() ]
        findings += [ self.resourcegroupstaggingapi_2() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def get_tag_keys(self):
        # create unique list
        tag_keys = set()
        logging.info("getting tag keys")

        for region in self.regions:
            client = self.session.client('resourcegroupstaggingapi', region_name=region)
            try:
                response = client.get_tag_keys()
                while True:
                    pagination_token = response["PaginationToken"]
                    for i in response["TagKeys"]:
                        tag_keys.add(i)
                    if pagination_token:
                        response = client.get_tag_keys(PaginationToken=pagination_token)
                    else:
                        break
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting tag keys - %s" % e.response["Error"]["Code"])
        return list(tag_keys)

    def get_tag_values(self):
        tag_values = {}
        logging.info("getting tag values")

        for region in self.regions:
            client = self.session.client('resourcegroupstaggingapi', region_name=region)

            for key in self.tag_keys:
                if key not in tag_values:
                    tag_values[key] = []

                try:
                    response = client.get_tag_values(Key=key)
                    while True:
                        pagination_token = response["PaginationToken"]
                        if response["TagValues"]:
                            for i in response["TagValues"]:
                                tag_values[key].append(i)
                        if pagination_token:
                            response = client.get_tag_values(Key=key, PaginationToken=pagination_token)
                        else:
                            break
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting tag values - %s" % e.response["Error"]["Code"])

        return tag_values

    def get_all_resources(self):
        all_resources = []
        logging.info("getting all resources")
        for region in self.regions:
            client = self.session.client('resourcegroupstaggingapi', region_name=region)
            try:
                response = client.get_resources()
                while True:
                    pagination_token = response["PaginationToken"]
                    all_resources = all_resources + response["ResourceTagMappingList"]
                    if pagination_token:
                        response = client.get_resources(PaginationToken=pagination_token)
                    else:
                        break
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting all resources - %s" % e.response["Error"]["Code"])

        return all_resources

    def resourcegroupstaggingapi_1(self):

        results = {
            "id" : "resourcegroupstaggingapi_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resourcegroupstaggingapi",
            "name" : "Ensure Tags Do Not Contain Sensitive or PII Data (Manual)",
            "affected": [],
            "analysis" : "",
            "description" : "This check lists all the tags being used in your account. It is possible for attackers to enumerate valid Tag keys and their corresponding values, therefore tags should not be used to store PII, confidential or otherwise sensitive information.",
            "remediation" : "Review the in use tags and remove any that contain sensitive information",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score" : "5.9",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if self.tag_values:
            results["analysis"] = self.tag_values
            results["affected"].append(self.account_id)
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "No Tags In Use"
            results["affected"].append(self.account_id)
            results["pass_fail"] = "PASS"

        return results


    def resourcegroupstaggingapi_2(self):

        results = {
            "id" : "resourcegroupstaggingapi_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resourcegroupstaggingapi",
            "name" : "All Resources",
            "affected": [],
            "analysis" : "",
            "description" : "A list of all resources (ARNs) in the account",
            "remediation" : "",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if self.all_resources:
            results["analysis"] = [ i["ResourceARN"] for i in self.all_resources]
            results["affected"].append(self.account_id)
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "No Resources Found"
            results["affected"].append(self.account_id)
            results["pass_fail"] = "PASS"

        return results

