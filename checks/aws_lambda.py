import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class aws_lambda(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.functions = self.list_functions()

    def run(self):
        findings = []
        findings += [ self.lambda_1() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def list_functions(self):
        functions = {}
        logging.info("getting functions")
        for region in self.regions:
            client = self.session.client('lambda', region_name=region)
            try:
                functions[region] = client.list_functions()["Functions"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting functions - %s" % e.response["Error"]["Code"])
        return functions
    
    def lambda_1(self):
        # Lambda functions environment variables (check for secrets)

        results = {
            "id" : "lambda_1",
            "ref" : "",
            "compliance" : "",
            "level" : "N/A",
            "service" : "lambda",
            "name" : "Lambda Function Environment Variables (Check for Secrets)",
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

        environment = {}

        for region, functions in self.functions.items():
            for function in functions:
                try:
                    environment[function["FunctionName"]] = function["Environment"]
                    results["affected"].append(function["FunctionName"])
                except KeyError:
                    pass
        

        if results["affected"]:
            results["analysis"] = json.dumps(environment)
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No environment vars in use"
            results["pass_fail"] = "PASS"

        return results


