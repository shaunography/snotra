import boto3
import json
import logging

from utils.utils import describe_regions

from datetime import datetime
from datetime import timedelta

class apigateway(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.apis = self.get_apis()
        self.stages = self.get_stages()

    def run(self):
        findings = []
        findings += [ self.apigateway_1() ]
        findings += [ self.apigateway_2() ]
        #findings += [ self.apigateway_3() ]
        findings += [ self.apigateway_4() ]
        #findings += [ self.apigateway_5() ]
        #findings += [ self.apigateway_6() ]
        findings += [ self.apigateway_7() ]
        return findings
    
    def get_apis(self):
        # returns APIs
        logging.info("Getting APIs")
        apis = {}
        for region in self.regions:
            client = self.session.client('apigatewayv2', region_name=region)
            try:
                apis[region] = client.get_apis()["Items"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting certificate list - %s" % e.response["Error"]["Code"])
        return apis

    def get_stages(self):
        # returns APIs
        logging.info("Getting Stages")
        stages = {}
        for region, apis in self.apis.items():
            client = self.session.client('apigatewayv2', region_name=region)
            for api in apis:
                api_id = api["ApiId"]
                try:
                    stages[api_id] = client.get_stages(ApiId=api_id)["Items"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting certificate list - %s" % e.response["Error"]["Code"])
        return stages

    def apigateway_1(self):
        # API Gateway REST and WebSocket API logging should be enabled

        results = {
            "id" : "apigateway_1",
            "ref" : ["APIGateway.1"],
            "compliance" : ["foundational"],
            "level" : "",
            "service" : "apigateway",
            "name" : "API Gateway REST and WebSocket API logging should be enabled",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether all stages of an Amazon API Gateway REST or WebSocket API have logging enabled. The control fails if logging is not enabled for all methods of a stage or if loggingLevel is neither ERROR nor INFO.\nAPI Gateway REST or WebSocket API stages should have relevant logs enabled. API Gateway REST and WebSocket API execution logging provides detailed records of requests made to API Gateway REST and WebSocket API stages. The stages include API integration backend responses, Lambda authorizer responses, and the requestId for AWS integration endpoints.",
            "remediation" : "To enable logging for REST and WebSocket API operations, see Set up CloudWatch API logging using the API Gateway console in the API Gateway Developer Guide.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for api_id, stages in self.stages.items():
            for stage in stages:
                #default_route_settings = stage["DefaultRouteSettings"]
                #route_settings = stage["RouteSettings"]["LoggingLevel"]
                try:
                    if stage["RouteSettings"]["LoggingLevel"] == "OFF":
                        results["affected"].append(api_id)
                except KeyError:
                    results["affected"].append(api_id)


        if results["affected"]:
            results["analysis"] = "The affected API Gateways do not have logging enabled on every stage."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
        
        return results

    def apigateway_2(self):
        # API Gateway REST API stages should be configured to use SSL certificates for backend authentication

        results = {
            "id" : "apigateway_2",
            "ref" : ["APIGateway.2"],
            "compliance" : ["foundational"],
            "level" : "",
            "service" : "apigateway",
            "name" : "API Gateway REST API stages should be configured to use SSL certificates for backend authentication",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether Amazon API Gateway REST API stages have SSL certificates configured. Backend systems use these certificates to authenticate that incoming requests are from API Gateway.\nAPI Gateway REST API stages should be configured with SSL certificates to allow backend systems to authenticate that requests originate from API Gateway.",
            "remediation" : "For detailed instructions on how to generate and configure API Gateway REST API SSL certificates, see Generate and configure an SSL certificate for backend authentication in the API Gateway Developer Guide.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for api_id, stages in self.stages.items():
            for stage in stages:
                try:
                    client_certificate_id = stage["ClientCertificateId"]
                except KeyError:
                    results["affected"].append("{}({})".format(stage["StageName"], api_id))


        if results["affected"]:
            results["analysis"] = "The affected API Gateway Stages do not have SSL certificates configured for backend authentication."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
        
        return results

    def apigateway_3(self):
        # API Gateway REST API stages should have AWS X-Ray tracing enabled

        results = {
            "id" : "apigateway_3",
            "ref" : ["APIGateway.3"],
            "compliance" : ["foundational"],
            "level" : "",
            "service" : "apigateway",
            "name" : "API Gateway REST API stages should be configured to use SSL certificates for backend authentication",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether AWS X-Ray active tracing is enabled for your Amazon API Gateway REST API stages.\nX-Ray active tracing enables a more rapid response to performance changes in the underlying infrastructure. Changes in performance could result in a lack of availability of the API. X-Ray active tracing provides real-time metrics of user requests that flow through your API Gateway REST API operations and connected services.",
            "remediation" : "For detailed instructions on how to enable X-Ray active tracing for API Gateway REST API operations, see Amazon API Gateway active tracing support for AWS X-Ray in the AWS X-Ray Developer Guide.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        #for api_id, stages in self.stages.items():
        #    for stage in stages:
        #        try:
        #            client_certificate_id = stage["ClientCertificateId"]
        #        except KeyError:
        #            results["affected"].append("{}({})".format(stage["StageName"], api_id))


        if results["affected"]:
            results["analysis"] = "The affected API Gateway Stages do not have SSL certificates configured for backend authentication."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
        
        return results

    def apigateway_4(self):
        # API Gateway should be associated with an AWS WAF web ACL

        results = {
            "id" : "apigateway_4",
            "ref" : ["APIGateway.4"],
            "compliance" : ["foundational"],
            "level" : "",
            "service" : "apigateway",
            "name" : "API Gateway should be associated with an AWS WAF web ACL",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an API Gateway stage uses an AWS WAF web access control list (ACL). This control fails if an AWS WAF web ACL is not attached to a REST API Gateway stage.\nAWS WAF is a web application firewall that helps protect web applications and APIs from attacks. It enables you to configure an ACL, which is a set of rules that allow, block, or count web requests based on customizable web security rules and conditions that you define. Ensure that your API Gateway stage is associated with an AWS WAF web ACL to help protect it from malicious attacks.",
            "remediation" : "For information on how to use the API Gateway console to associate an AWS WAF Regional web ACL with an existing API Gateway API stage, see Using AWS WAF to protect your APIs in the API Gateway Developer Guide.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, apis in self.apis.items():
            client = self.session.client('wafv2', region_name=region)
            for api in apis:
                for stage in self.stages[api["ApiId"]]:
                    try:
                        acl = client.get_web_acl_for_resource(ResourceArn="arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}".format(region=region,api_id=api["ApiId"], stage_name=stage["StageName"]))["WebACL"]
                    except KeyError:
                        results["affected"].append("{}({})".format(stage["StageName"], api["ApiId"]))
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting Web ACL - %s" % e.response["Error"]["Code"])

        if results["affected"]:
            results["analysis"] = "The affected API Gateway Stages are not associated with an AWS WAF Web ACL."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
        
        return results

    def apigateway_5(self):
        # API Gateway REST API cache data should be encrypted at rest

        results = {
            "id" : "apigateway_5",
            "ref" : ["APIGateway.5"],
            "compliance" : ["foundational"],
            "level" : "",
            "service" : "apigateway",
            "name" : "API Gateway REST API cache data should be encrypted at rest",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether all methods in API Gateway REST API stages that have cache enabled are encrypted. The control fails if any method in an API Gateway REST API stage is configured to cache and the cache is not encrypted.\nEncrypting data at rest reduces the risk of data stored on disk being accessed by a user not authenticated to AWS. It adds another set of access controls to limit unauthorized users ability access the data. For example, API permissions are required to decrypt the data before it can be read.\nAPI Gateway REST API caches should be encrypted at rest for an added layer of security.",
            "remediation" : "To remediate this control, configure the stage to encrypt the cache data.Open the API Gateway console at https://console.aws.amazon.com/apigateway/\n1. Choose the API.\n2. Choose Stages.\n3. In the Stages list for the API, choose the stage to add caching to.\n4. Choose Settings.\n5. Choose Enable API cache.\n6. Update the desired settings, then select Encrypt cache data.\n7. Choose Save Changes.\n",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for api_id, stages in self.stages.items():
            for stage in stages:
                try:
                    print(stage)
                    #client_certificate_id = stage["ClientCertificateId"]
                except KeyError:
                    results["affected"].append("{}({})".format(stage["StageName"], api_id))


        if results["affected"]:
            results["analysis"] = "The affected API Gateway Stages do not have SSL certificates configured for backend authentication."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
        
        return results

    def apigateway_6(self):
        # API Gateway routes should specify an authorization type

        results = {
            "id" : "apigateway_6",
            "ref" : ["APIGateway.8"],
            "compliance" : ["foundational"],
            "level" : "",
            "service" : "apigateway",
            "name" : "API Gateway routes should specify an authorization type",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks if Amazon API Gateway routes have an authorization type. The control fails if the API Gateway route does not specify an authorization type.\nAPI Gateway supports multiple mechanisms for controlling and managing access to your API. By specifying an authorization type, you can restrict access to your API to only authorized users or processes.",
            "remediation" : "To set an authorization type for HTTP APIs, see Controlling and managing access to an HTTP API in API Gateway in the API Gateway Developer Guide. To set an authorization type for WebSocket APIs, see Controlling and managing access to a WebSocket API in API Gateway in the API Gateway Developer Guide.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for api_id, stages in self.stages.items():
            for stage in stages:
                try:
                    print(stage)
                    #client_certificate_id = stage["ClientCertificateId"]
                except KeyError:
                    results["affected"].append("{}({})".format(stage["StageName"], api_id))


        if results["affected"]:
            results["analysis"] = "The affected API Gateway Stages do not have SSL certificates configured for backend authentication."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
        
        return results

    def apigateway_7(self):
        # Access logging should be configured for API Gateway V2 Stages

        results = {
            "id" : "apigateway_7",
            "ref" : ["APIGateway.9"],
            "compliance" : ["foundational"],
            "level" : "",
            "service" : "apigateway",
            "name" : "Access logging should be configured for API Gateway V2 Stages",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks if Amazon API Gateway V2 stages have access logging configured. This control fails if access log settings aren't defined.\nAPI Gateway access logs provide detailed information about who has accessed your API and how the caller accessed the API. These logs are useful for applications such as security and access audits and forensics investigation. Enable these access logs to analyze traffic patterns and to troubleshoot issues.",
            "remediation" : "To set up access logging, see Set up CloudWatch API logging using the API Gateway console in the API Gateway Developer Guide. ",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for api_id, stages in self.stages.items():
            for stage in stages:            
                try:
                    access_log_settings =  stage["AccessLogSettings"]
                except KeyError:
                    results["affected"].append("{}({})".format(stage["StageName"], api_id))


        if results["affected"]:
            results["analysis"] = "The affected API Gateway Stages do not access loggin enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
        
        return results