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
        self.functions_get = self.get_functions()
        self.policies = self.get_policies()

    def run(self):
        findings = []
        findings += [ self.lambda_1() ]
        findings += [ self.lambda_2() ]
        findings += [ self.lambda_3() ]
        findings += [ self.lambda_4() ]
        findings += [ self.lambda_5() ]
        findings += [ self.lambda_6() ]
        return findings

    def cis(self):
        findings += [ self.lambda_2() ]
        findings += [ self.lambda_3() ]
        findings += [ self.lambda_4() ]
        findings += [ self.lambda_6() ]
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

    def get_functions(self):
        functions_dict = {}
        logging.info("getting functions")
        for region, functions in self.functions.items():
            client = self.session.client('lambda', region_name=region)
            functions_dict[region] = []
            for function in functions:
                try:
                    functions_dict[region].append(client.get_function(FunctionName=function["FunctionName"])["Configuration"])
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting function- %s" % e.response["Error"]["Code"])
        return functions_dict

    def get_policies(self):
        policies = {}
        logging.info("getting functions")
        for region, functions in self.functions.items():
            client = self.session.client('lambda', region_name=region)
            policies[region] = {}
            for function in functions:
                policies[region][function["FunctionName"]] = []
                try:
                    policies[region][function["FunctionName"]].append(client.get_policy(FunctionName=function["FunctionName"])["Policy"])
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting policy - %s" % e.response["Error"]["Code"])
        return policies
    
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
            results["analysis"] = environment
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No environment vars in use"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def lambda_2(self):
        # Ensure Cloudwatch Lambda insights is enabled (CIS)

        results = {
            "id" : "lambda_2",
            "ref" : "4.2",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "lambda",
            "name" : "Ensure Cloudwatch Lambda insights is enabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Ensure that Amazon CloudWatch Lambda Insights is enabled for your Amazon Lambda functions for enhanced monitoring. Amazon CloudWatch Lambda Insights allows you to monitor, troubleshoot, and optimize your Lambda functions. The service collects system-level metrics and summarizes diagnostic information to help you identify issues with your Lambda functions and resolve them as soon as possible. CloudWatch Lambda Insights collects system-level metrics and emits a single performance log event for every invocation of that Lambda function.",
            "remediation" : "From the Console:\n1. Login to AWS Console using https://console.aws.amazon.com/lambda/\n2. Click Functions.\n3. Click on the name of the function.\n4. Click on the Configuration tab\n5. Click on 'Monitoring and operations tools'.\n6. In the Monitoring and operations tools section click Edit to update the monitoring configuration\n7. In the CloudWatch Lambda Insights section click the Enhanced monitoring button to enable\n***Note - When you enable the feature using the AWS Management Console, Amazon Lambda adds the required permissions to your function's execution role.\n8. Click Save\n9. Repeat steps 2-8 for each Lambda function within the current region that fails the Audit.\n10. Then repeat the Audit process for all other regions.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, functions in self.functions_get.items():
            for function in functions:
                try:
                    enabled = False
                    for layer in function["Layers"]:
                        if "LambdaInsightsExtension" in layer["Arn"]:
                            enabled = True
                except KeyError:
                    pass

                if not enabled:
                    results["affected"].append(function["FunctionName"])

        if results["affected"]:
            results["analysis"] = "The affected Lambda functions do not have CloudWatch Lambda Insights enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def lambda_3(self):
        # Ensure every Lambda function has its own IAM Role (CIS)

        results = {
            "id" : "lambda_3",
            "ref" : "4.5",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "lambda",
            "name" : "Ensure every Lambda function has its own IAM Role (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Every Lambda function should have a one to one IAM execution role and the roles should not be shared between functions. The Principle of Least Privilege means that any Lambda function should have the minimal amount of access required to perform its tasks. In order to accomplish this Lambda functions should not share IAM Execution roles.",
            "remediation" : "From the Console\n1. Login to the AWS console using https://console.aws.amazon.com/lambda/\n2. In the left column, under AWS Lambda, click Functions.\n3. Under Function name click on the name of the function that you want to change/update.\n4. Click the Configuration tab\n5. Under General configuration on the left column, click Permissions.\n6. Under the Execution role section, click Edit.\n7. Scroll down to Execution role To use an existing IAM role",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        roles = []

        for region, functions in self.functions_get.items():
            roles = [ function["Role"] for function in functions ]
            duplicated_roles = [x for x in roles if roles.count(x) >= 2]

            for function in functions:
                if function["Role"] in duplicated_roles:
                    results["affected"].append(function["FunctionName"])

        if results["affected"]:
            results["analysis"] = "The affected Lambda functions are using an IAM role which is shared with another function."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def lambda_4(self):
        # Ensure Lambda functions are not exposed to everyone (CIS)

        results = {
            "id" : "lambda_4",
            "ref" : "4.6",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "lambda",
            "name" : "Ensure Lambda functions are not exposed to everyone (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "A publicly accessible Amazon Lambda function is open to the public and can be reviewed by anyone. To protect against unauthorized users that are sending requests to invoke these functions they need to be changed so they are not exposed to the public. Allowing anyone to invoke and run your Amazon Lambda functions can lead to data exposure, data loss, and unexpected charges on your AWS bill.",
            "remediation" : "From the Console\n1. Login to the AWS Console using https://console.aws.amazon.com/lambda/.\n2. In the left column, under AWS Lambda, click Functions.\n3. Under Function name click on the name of the function that you want to review\n4. Click the Configuration tab\n5. In the left column, click Permissions.\n6. In the Resource-based policy section, perform the following actions:\n• Under Policy statements\n• Select the policy statement that allows anonymous access\n• Click Delete to remove the non-compliant statement from the resource-based policy attached\n• Within the Delete statement confirmation box, click Remove\n• Click Add permissions to add a new policy statement that grants permissions to a trusted entity only.\n• On the Add permissions page configure the new policy statement to grant access to another AWS account, IAM user, IAM role, or to another AWS service.\n• Click Save\n7. Repeat steps no. 2 – 6 for each Lambda function that fails the Audit above, within the current region.\n8. Repeat this Audit for all the other AWS regions.",
            "impact" : "high",
            "probability" : "high",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score" : "8.1",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, functions in self.policies.items():
            for function, policies in functions.items():
                for policy in policies:
                    for statement in json.loads(policy)["Statement"]:
                        if statement["Effect"] == "Allow":
                            try:
                                if statement["Principal"]["AWS"] == "*":
                                    if "Condition" not in statement:
                                        results["affected"].append(function)
                            except KeyError:
                                pass
                            except TypeError:
                                pass

                            try:
                                if statement["Principal"] == "*":
                                    if "Condition" not in statement:
                                        results["affected"].append(function)
                            except KeyError:
                                pass
                            except TypeError:
                                pass

                            try:
                                if statement["Principal"] == "":
                                    if "Condition" not in statement:
                                        results["affected"].append(function)
                            except KeyError:
                                pass
                            except TypeError:
                                pass

        if results["affected"]:
            results["analysis"] = "The affected Lambda functions have a resource based policy which allows access to any AWS principal"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def lambda_5(self):
        # Lambda Functions With Resource Based Policies Configured (Manual)

        results = {
            "id" : "lambda_5",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "lambda",
            "name" : "Lambda Functions With Resource Based Policies Configured (Manual)",
            "affected": [],
            "analysis" : {},
            "description" : "Lambda supports resource-based permissions policies for Lambda functions and layers. Resource-based policies let you grant usage permission to other AWS accounts or organizations on a per-resource basis. You also use a resource-based policy to allow an AWS service to invoke your function on your behalf.",
            "remediation" : "Ensure Resource Based Policies are configured following the principle of least privilege and only allow access from trusted AWS principals",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, functions in self.policies.items():
            for function, policies in functions.items():
                if policies:
                    results["analysis"][function] = policies
                    results["affected"].append(function)


        if results["affected"]:
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "No policies found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def lambda_6(self):
        # Ensure that Code Signing is enabled for Lambda functions (CIS)

        results = {
            "id" : "lambda_6",
            "ref" : "4.8",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "lambda",
            "name" : "Ensure that Code Signing is enabled for Lambda functions (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Ensure that all your Amazon Lambda functions are configured to use the Code Signing feature in order to restrict the deployment of unverified code. Code Signing, ensures that the function code is signed by an approved (trusted) source, and that it has not been altered since signing, and that the code signature has not expired or been revoked.",
            "remediation" : "Ensure all Lambda code is signed",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, functions in self.functions.items():
            client = self.session.client('lambda', region_name=region)
            for function in functions:
                try:
                    config = client.get_function_code_signing_config(FunctionName=function["FunctionName"])["CodeSigningConfigArn"]
                except KeyError:
                    results["affected"].append(function["FunctionName"])
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error code signing config - %s" % e.response["Error"]["Code"])

        if results["affected"]:
            results["analysis"] = "The affected Lambda functions do not have code signing enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
