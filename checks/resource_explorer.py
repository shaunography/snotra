import boto3
import json
import re
import logging

from utils.utils import get_account_id
from utils.utils import describe_regions

class resource_explorer(object):

    def __init__(self, session):
        self.session = session
        self.account_id = get_account_id(session)
        self.regions = describe_regions(session)
        self.indexes = self.list_indexes()

    def run(self):
        findings = []
        findings += [ self.resource_explorer_1() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def list_indexes(self):
        # returns list of resource explorer indexes
        logging.info("Getting Indexes")
        indexes = {}
        for region in self.regions:
            client = self.session.client('resource-explorer-2', region_name=region)
            try:
                indexes[region]= client.list_indexes()["Indexes"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting indexes - %s" % e.response["Error"]["Code"])
        return indexes

    
    def resource_explorer_1(self):
        # Resource Explorer indexes not found

        results = {
            "id" : "resourceexplorer_1",
            "ref" : "",
            "compliance" : "",
            "level" : "N/A",
            "service" : "resourseexplorer",
            "name" : "Resource Explorer Indexes Not Found",
            "affected": [],
            "analysis" : "",
            "description" : "AWS Resource explorer is not enabled. AWS Resource Explorer is a resource search and discovery service. With Resource Explorer, you can explore your resources, such as Amazon Elastic Compute Cloud instances, Amazon Kinesis streams, or Amazon DynamoDB tables, using an internet search engine-like experience. You can search for your resources using resource metadata like names, tags, and IDs. Resource Explorer works across AWS Regions in your account to simplify your cross-Region workloads. Not having Resource Explorer indexes can result in increased complexity and overhead in managing your resources, as well as increased risk of security and compliance issues.",
            "remediation" : "Enable Resource Explorer for all regions\nMore Information\nhttps://docs.aws.amazon.com/resource-explorer/latest/userguide/manage-service-turn-on-region.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, indexes in self.indexes.items():
            if not indexes:
                results["affected"].append(region)

        if results["affected"]:
            results["analysis"] = "The affected regions do not have any active resource explorer indexes"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "Indexes are enabled in all regions"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
