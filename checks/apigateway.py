import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

class apigateway(object):

    def __init__(self, session):
        self.regions = describe_regions(session)
        self.session = session
        self.account_id = get_account_id(session)
        self.apis = self.get_apis()
        self.rest_apis = self.get_rest_apis()
        self.authorizers = self.get_authorizers()

    def run(self):
        findings = []
        findings += [ self.apigateway_1() ]
        findings += [ self.apigateway_2() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.apigateway_1() ]
        findings += [ self.apigateway_2() ]
        return findings

    def get_rest_apis(self):
        apis = {}
        logging.info("getting rest apis")
        for region in self.regions:
            client = self.session.client('apigateway', region_name=region)
            try:
                items = client.get_rest_apis()["items"]
                if items:
                    apis[region] = items
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting rest apis - %s" % e.response["Error"]["Code"])
        return apis

    def get_apis(self):
        apis = {}
        logging.info("getting apis")
        for region in self.regions:
            client = self.session.client('apigatewayv2', region_name=region)
            try:
                items = client.get_apis()["Items"]
                if items:
                    apis[region] = items
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting apis - %s" % e.response["Error"]["Code"])
        return apis

    def get_authorizers(self):
        authorizers = {}
        logging.info("getting authorizers")

        for region, rest_apis in self.rest_apis.items():
            client = self.session.client('apigateway', region_name=region)
            for rest_api in rest_apis:
                try:
                    items = client.get_authorizers(restApiId=rest_api["id"])["items"]
                    if items:
                        authorizers[rest_api["id"]] = items
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting authorizers - %s" % e.response["Error"]["Code"])

        for region, apis in self.apis.items():
            client = self.session.client('apigatewayv2', region_name=region)
            for api in apis:
                try:
                    items = client.get_authorizers(ApiId=api["ApiId"])["Items"]
                    if items:
                        authorizers[api["ApiId"]] = items
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting authorizers - %s" % e.response["Error"]["Code"])

        return authorizers

    def apigateway_1(self):
        # api gateways in use

        results = {
            "id" : "apigateway_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "apigateway",
            "name" : "API Gateways In Use",
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

        apis = {}
        if self.apis:
            apis["apis"] = self.apis
        if self.rest_apis:
            apis["rest_apis"] = self.rest_apis

        if apis:
            results["affected"].append(self.account_id)
            results["analysis"] = apis
            results["pass_fail"] = "INFO"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No APIs in use"

        return results

    def apigateway_2(self):
        # api gateways using lambda authorizers

        results = {
            "id" : "apigateway_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "apigateway",
            "name" : "API Gateways Using Lambda Authorizers",
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

        if self.authorizers:
            results["affected"].append(self.account_id)
            results["analysis"] = self.authorizers
            results["pass_fail"] = "INFO"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No Authorizers in use"

        return results

