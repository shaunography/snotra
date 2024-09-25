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
        self.stages = self.get_stages()
        self.stages_v2 = self.get_stages_v2()
        self.routes = self.get_routes()
        self.authorizers = self.get_authorizers()

    def run(self):
        findings = []
        findings += [ self.apigateway_1() ]
        findings += [ self.apigateway_2() ]
        findings += [ self.apigateway_3() ]
        findings += [ self.apigateway_4() ]
        findings += [ self.apigateway_5() ]
        findings += [ self.apigateway_6() ]
        findings += [ self.apigateway_7() ]
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

    def get_stages(self):
        stages = {}
        logging.info("getting stages")

        for region, rest_apis in self.rest_apis.items():
            client = self.session.client('apigateway', region_name=region)
            for rest_api in rest_apis:
                try:
                    items = client.get_stages(restApiId=rest_api["id"])["item"]
                    if items:
                        stages[rest_api["id"]] = items
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting stages - %s" % e.response["Error"]["Code"])

        return stages

    def get_stages_v2(self):
        stages = {}
        logging.info("getting stages v2")

        for region, apis in self.apis.items():
            client = self.session.client('apigatewayv2', region_name=region)
            for api in apis:
                try:
                    items = client.get_stages(ApiId=api["ApiId"])["Items"]
                    if items:
                        stages[api["ApiId"]] = items
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting stages - %s" % e.response["Error"]["Code"])

        return stages

    def get_routes(self):
        routes = {}
        logging.info("getting routes")

        for region, apis in self.apis.items():
            client = self.session.client('apigatewayv2', region_name=region)
            for api in apis:
                try:
                    items = client.get_routes(ApiId=api["ApiId"])["Items"]
                    if items:
                        routes[api["ApiId"]] = items
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting routes - %s" % e.response["Error"]["Code"])

        return routes


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

        results["analysis"] = {}

        for id, items in self.authorizers.items():
            analysis = []
            for authorizer in items:
                try:
                    if authorizer["AuthorizerType"] == "REQUEST":
                        analysis.append(authorizer)
                except KeyError:
                    pass
                try:
                    if authorizer["type"] == "REQUEST":
                        analysis.append(authorizer)
                except KeyError:
                    pass
            if analysis:
                results["affected"].append(id)
                results["analysis"][id] = analysis

        if results["affected"]:
            results["pass_fail"] = "INFO"
        elif self.authorizers:
            results["affected"].append(self.account_id)
            results["analysis"] = "No Lambda authorizers in use"
            results["pass_fail"] = "PASS"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No API Gateway Authorizers in use"

        return results

    def apigateway_3(self):
        # API Gateway REST and WebSocket API execution logging should be enabled

        results = {
            "id" : "apigateway_3",
            "ref" : "APIGateway.1",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "apigateway",
            "name" : "API Gateway REST and WebSocket API execution logging should be enabled",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether all stages of an Amazon API Gateway REST or WebSocket API have logging enabled. The control fails if the loggingLevel isn't ERROR or INFO for all stages of the API. Unless you provide custom parameter values to indicate that a specific log type should be enabled, Security Hub produces a passed finding if the logging level is either ERROR or INFO. API Gateway REST or WebSocket API stages should have relevant logs enabled. API Gateway REST and WebSocket API execution logging provides detailed records of requests made to API Gateway REST and WebSocket API stages. The stages include API integration backend responses, Lambda authorizer responses, and the requestId for AWS integration endpoints.",
            "remediation" : "To enable logging for REST and WebSocket API operations, see Set up CloudWatch API logging using the API Gateway console in the API Gateway Developer Guide.\nMore Information:\nhttps://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#set-up-access-logging-using-console",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = {}

        for api, stages in self.stages.items():
            for stage in stages:
                try:
                    if stage["methodSettings"]["loggingLevel"] == "OFF":
                        results["affected"].append(api)
                except KeyError:
                    results["affected"].append(api)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "The affected API Gateways have stages without logging enabled"
        elif self.stages:
            results["affected"].append(self.account_id)
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No API Gateway Stages in use"

        return results

    def apigateway_4(self):
        # API Gateway REST API stages should have AWS X-Ray tracing enabled

        results = {
            "id" : "apigateway_4",
            "ref" : "APIGateway.3",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "apigateway",
            "name" : "API Gateway REST API stages should have AWS X-Ray tracing enabled",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether AWS X-Ray active tracing is enabled for your Amazon API Gateway REST API stages. X-Ray active tracing enables a more rapid response to performance changes in the underlying infrastructure. Changes in performance could result in a lack of availability of the API. X-Ray active tracing provides real-time metrics of user requests that flow through your API Gateway REST API operations and connected services.",
            "remediation" : "For detailed instructions on how to enable X-Ray active tracing for API Gateway REST API operations, see Amazon API Gateway active tracing support for AWS X-Ray in the AWS X-Ray Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/xray/latest/devguide/xray-services-apigateway.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = {}

        for api, stages in self.stages.items():
            for stage in stages:
                if stage["tracingEnabled"] == False:
                    results["affected"].append(api)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "The affected API Gateways do not have X-Ray tracing enabled"
        elif self.stages:
            results["affected"].append(self.account_id)
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No API Gateway Stages in use"

        return results

    def apigateway_5(self):
        # API Gateway REST API cache data should be encrypted at rest

        results = {
            "id" : "apigateway_5",
            "ref" : "APIGateway.5",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "apigateway",
            "name" : "API Gateway REST API cache data should be encrypted at rest",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether all methods in API Gateway REST API stages that have cache enabled are encrypted. The control fails if any method in an API Gateway REST API stage is configured to cache and the cache is not encrypted. Security Hub evaluates the encryption of a particular method only when caching is enabled for that method. Encrypting data at rest reduces the risk of data stored on disk being accessed by a user not authenticated to AWS. It adds another set of access controls to limit unauthorized users ability access the data. For example, API permissions are required to decrypt the data before it can be read. API Gateway REST API caches should be encrypted at rest for an added layer of security.",
            "remediation" : "To configure API caching for a stage, see Enable Amazon API Gateway caching in the API Gateway Developer Guide. In Cache Settings, choose Encrypt cache data.\nMore Information\nhttps://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html#enable-api-gateway-caching",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = {}

        for api, stages in self.stages.items():
            for stage in stages:
                try:
                    if stage["methodSettings"]["cachingEnabled"] == True:
                        if stage["methodSettings"]["cacheDataEncrypted"] == False:
                            results["affected"].append(api)
                except KeyError:
                    pass

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "The affected API Gateways have stages which use caching but the caches are not encrypted."
        elif self.stages:
            results["affected"].append(self.account_id)
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No API Gateway Stages in use"

        return results

    def apigateway_6(self):
        # API Gateway routes should specify an authorization type

        results = {
            "id" : "apigateway_6",
            "ref" : "APIGateway.8",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "apigateway",
            "name" : "API Gateway routes should specify an authorization type",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks if Amazon API Gateway routes have an authorization type. The control fails if the API Gateway route doesn't have any authorization type. Optionally, you can provide a custom parameter value if you want the control to pass only if the route uses the authorization type specified in the authorizationType parameter. API Gateway supports multiple mechanisms for controlling and managing access to your API. By specifying an authorization type, you can restrict access to your API to only authorized users or processes.",
            "remediation" : "To set an authorization type for HTTP APIs, see Controlling and managing access to an HTTP API in API Gateway in the API Gateway Developer Guide. To set an authorization type for WebSocket APIs, see Controlling and managing access to a WebSocket API in API Gateway in the API Gateway Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control.html\nhttps://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-control-access.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = {}

        for api, routes in self.routes.items():
            for route in routes:
                if route["AuthorizationType"] == "NONE":
                    results["affected"].append(api)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "The affected API Gateways have routes which do not have authorisation enabled."
        elif self.routes:
            results["affected"].append(self.account_id)
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No API Gateway Stages in use"

        return results

    def apigateway_7(self):
        # Access logging should be configured for API Gateway V2 Stages

        results = {
            "id" : "apigateway_7",
            "ref" : "APIGateway.9",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "apigateway",
            "name" : "Access logging should be configured for API Gateway V2 Stages",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks if Amazon API Gateway V2 stages have access logging configured. This control fails if access log settings aren't defined. API Gateway access logs provide detailed information about who has accessed your API and how the caller accessed the API. These logs are useful for applications such as security and access audits and forensics investigation. Enable these access logs to analyze traffic patterns and to troubleshoot issues. For additional best practices, see Monitoring REST APIs in the API Gateway Developer Guide.",
            "remediation" : "To set up access logging, see Set up CloudWatch API logging using the API Gateway console in the API Gateway Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#set-up-access-logging-using-console",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        results["analysis"] = {}

        for api, stages in self.stages_v2.items():
            for stage in stages:
                try:
                    logs = stage["AccessLogSettings"]
                except KeyError:
                    results["affected"].append(api)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "The affected API Gateways V2 do not have access logs enabled"
        elif self.stages:
            results["affected"].append(self.account_id)
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No API Gateway Stages in use"

        return results
