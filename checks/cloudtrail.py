import boto3
import json
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

class cloudtrail(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.trails = self.get_trails()

    def run(self):
        findings = []
        findings += [ self.cloudtrail_1() ]
        findings += [ self.cloudtrail_2() ]
        findings += [ self.cloudtrail_3() ]
        findings += [ self.cloudtrail_4() ]
        findings += [ self.cloudtrail_5() ]
        findings += [ self.cloudtrail_6() ]
        findings += [ self.cloudtrail_7() ]
        findings += [ self.cloudtrail_8() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.cloudtrail_1() ]
        findings += [ self.cloudtrail_2() ]
        findings += [ self.cloudtrail_5() ]
        findings += [ self.cloudtrail_6() ]
        findings += [ self.cloudtrail_7() ]
        findings += [ self.cloudtrail_8() ]
        return findings
    
    def get_trails(self):
        trails = {}
        logging.info("getting trails")
        for region in self.regions:
            client = self.session.client('cloudtrail', region_name=region)
            try:
                trails[region] = client.describe_trails()["trailList"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting trails - %s" % e.response["Error"]["Code"])
        return trails

    def cloudtrail_1(self):
        # Ensure CloudTrail is enabled in all regions (Automated)

        results = {
            "id" : "cloudtrail_1",
            "ref" : "3.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail is enabled in all regions (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail provides a history of AWS API calls for an account, including API calls made via the Management Console, SDKs, command line tools, and higher-level AWS services (such as CloudFormation).",
            "remediation" : "Enable CloudTrail in all regions",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, trail_list in self.trails.items():
            client = self.session.client('cloudtrail', region_name=region)
            for trail in trail_list:
                trail_name = trail["Name"]
                if trail["IsMultiRegionTrail"] == True:
                    if trail["HomeRegion"] == region:
                        try:
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                results["affected"].append(trail_name)
                        except boto3.exceptions.botocore.exceptions.ClientError as e:
                            logging.error("Error getting trail status - %s" % e.response["Error"]["Code"])

        if results["affected"]:
            results["analysis"] = "The affected trails are multi region enabled."
            results["pass_fail"] = "PASS"
        else:
            results["affected"].append(self.account_id)
            results["analysis"] = "No multi region enabled trails were found."
            results["pass_fail"] = "FAIL"

        
        return results

    def cloudtrail_2(self):
        # Ensure CloudTrail log file validation is enabled (Automated)

        results = {
            "id" : "cloudtrail_2",
            "ref" : "3.2",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail log file validation is enabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was changed, deleted, or unchanged after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails. Enabling log file validation will provide additional integrity checking of CloudTrail logs.",
            "remediation" : "Enabled log file validation on all your trails",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, trail_list in self.trails.items():
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if trail["LogFileValidationEnabled"] == False:
                        results["affected"].append(trail["Name"])

        if results["affected"]:
            results["analysis"] = "The affected trails do not have log file validation enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "Log file validation is enabled on all trails."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        if not [ i for i in self.trails.values() if i ]:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"
            results["affected"].append(self.account_id)

        return results

    def cloudtrail_3(self):
        # Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible (Automated)

        results = {
            "id" : "cloudtrail_3",
            "ref" : "",
            "compliance" : "",
            "level" : "",
            "service" : "cloudtrail",
            "name" : "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
            "affected": [],
            "analysis" : "",
            "description" : "CloudTrail logs a record of every API call made in your AWS account. These logs file are stored in an S3 bucket. It is recommended that the bucket policy or access control list (ACL) applied to the S3 bucket that CloudTrail logs to prevent public access to the CloudTrail logs. Allowing public access to CloudTrail log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.",
            "remediation" : "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        s3_client = self.session.client('s3')
        
        for region, trail_list in self.trails.items():
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    bucket_name = trail["S3BucketName"]
                    trail_name = trail["Name"]
                    try:
                        grants = s3_client.get_bucket_acl(Bucket=bucket_name)["Grants"]
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting acl for bucket %s - %s" % (bucket_name, e.response["Error"]["Code"]))
                    else:
                        for grant in grants:
                            try:
                                if grant["Grantee"]["URI"] == "https://acs.amazonaws.com/groups/global/AllUsers":
                                    results["affected"].append(trail_name)
                                if grant["Grantee"]["URI"] == "https://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                                    results["affected"].append(trail_name)
                            except KeyError:
                                pass
                                        
                            try:
                                policy = json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"])
                            # botocore.exceptions.ClientError: An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist
                            except boto3.exceptions.botocore.exceptions.ClientError:
                                # no bucket policy exists
                                pass
                            else:
                                statements = policy["Statement"]
                                for statement in statements:
                                    effect = statement["Effect"]
                                    if effect == "Allow":
                                        try:
                                            if statement["Principal"]["AWS"] == "*":
                                                results["affected"].append(trail_name)
                                        except KeyError:
                                            pass

                                        try:
                                            if statement["Principal"]["Service"] == "*":
                                                results["affected"].append(trail_name)
                                        except KeyError:
                                            pass

        if results["affected"]:
            results["analysis"] = "The affected trails are using a potentially public S3 bucket."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No public cloud trail buckets found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        if not [ i for i in self.trails.values() if i ]:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results



    def cloudtrail_4(self):
        # Ensure CloudTrail trails are integrated with CloudWatch Logs (Automated)

        results = {
            "id" : "cloudtrail_4",
            "ref" : "",
            "compliance" : "",
            "level" : "",
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail trails are integrated with CloudWatch Logs",
            "affected": [],
            "analysis" : "",
            "description" : "AWS CloudTrail is a web service that records AWS API calls made in a given AWS account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 bucket for long term analysis, realtime analysis can be performed by configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs. Note: The intent of this recommendation is to ensure AWS account activity is being captured, monitored, and appropriately alarmed on. CloudWatch Logs is a native way to accomplish this using AWS services but does not preclude the use of an alternate solution. Sending CloudTrail logs to CloudWatch Logs will facilitate real-time and historic activity logging based on user, API, resource, and IP address, and provides opportunity to establish alarms and notifications for anomalous or sensitivity account activity. ",
            "remediation" : "Ensure CloudTrail trails are integrated with CloudWatch Logs",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, trail_list in self.trails.items():
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if "CloudWatchLogsLogGroupArn" not in trail:
                        results["affected"].append(trail["Name"])

        if results["affected"]:
            results["analysis"] = "The affected trails are not integrated with CloudWatch Logs."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All trails are integrated with CloudWatch Logs."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        if not [ i for i in self.trails.values() if i ]:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"
            results["affected"].append(self.account_id)

        return results


    def cloudtrail_5(self):
        # Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Automated)

        results = {
            "id" : "cloudtrail_5",
            "ref" : "3.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket. By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within any target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows.",
            "remediation" : "Ensure the CloudTrail S3 bucket has access logging is enabled",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        s3_client = self.session.client('s3')
        
        for region, trail_list in self.trails.items():
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        if "LoggingEnabled" not in s3_client.get_bucket_logging(Bucket=trail["S3BucketName"]):
                            results["affected"].append(trail["Name"])
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting logging for bucket %s - %s" % (trail["S3BucketName"], e.response["Error"]["Code"]))

        if not [ i for i in self.trails.values() if i ]:
            results["analysis"] = "no CloudTrail trails in use"
            results["pass_fail"] = "FAIL"
            results["affected"].append(self.account_id)
        
        if results["affected"]:
            results["analysis"] = "The affected trails do not have S3 bucket access logging enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "S3 bucket access logging is enabled."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    
    def cloudtrail_6(self):
        # Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Automated)

        results = {
            "id" : "cloudtrail_6",
            "ref" : "3.5",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail logs are encrypted at rest using KMS CMKs (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS. Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data as a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.",
            "remediation" : "Configure CloudTrail to use SSE-KMS for encryption at rest.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, trail_list in self.trails.items():
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if "KmsKeyId" not in trail:
                        results["affected"].append(trail["Name"])

        if results["affected"]:
            results["analysis"] = "The affected trails do not encrypt logs at rest."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "CloudTrail logs are encrypted at rest with KMS CMKs."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        if not [ i for i in self.trails.values() if i ]:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"
            results["affected"].append(self.account_id)

        return results

    def cloudtrail_7(self):
        # Ensure that Object-level logging for write events is enabled for S3 bucket (Automated)

        results = {
            "id" : "cloudtrail_7",
            "ref" : "3.8",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure that Object-level logging for write events is enabled for S3 bucket (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets. Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events.",
            "remediation" : "Enable S3 bucket Object-level logging for write events in CloudTrail",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }
        
        logging.info(results["name"])
     
        for region, trail_list in self.trails.items():
            client = self.session.client('cloudtrail', region_name=region)
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if trail["HasCustomEventSelectors"] == True:
                        trail_name = trail["Name"]
                        try:
                            event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"]
                        except boto3.exceptions.botocore.exceptions.ClientError as e:
                            logging.error("Error getting event selectors - %s" % e.response["Error"]["Code"])
                        except KeyError:
                            logging.error("Error no event selectors")
                        else:
                            for selector in event_selectors:
                                if selector["ReadWriteType"] == "All" or selector["ReadWriteType"] == "WriteOnly":
                                    for resources in selector["DataResources"]:
                                        if resources["Type"] == "AWS::S3::Object":
                                            results["affected"].append(trail_name)
        
        if results["affected"]:
            results["analysis"] = "The affected trails have S3 Object-Level logging for write events enabled."
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "No trails were found with S3 Object-Level Logging enabled."
            results["affected"].append(self.account_id)
            results["pass_fail"] = "FAIL"

        if not [ i for i in self.trails.values() if i ]:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"
            results["affected"].append(self.account_id)

        return results
    
    def cloudtrail_8(self):
        # Ensure that Object-level logging for read events is enabled for S3 bucket (Automated)

        results = {
            "id" : "cloudtrail_8",
            "ref" : "3.9",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure that Object-level logging for read events is enabled for S3 bucket (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets. Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity using Amazon CloudWatch Events.",
            "remediation" : "Enable S3 bucket Object-level logging for read events in CloudTrail",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
     
        for region, trail_list in self.trails.items():
            client = self.session.client('cloudtrail', region_name=region)
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if trail["HasCustomEventSelectors"] == True:
                        trail_name = trail["Name"]
                        try:
                            event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"]
                        except boto3.exceptions.botocore.exceptions.ClientError as e:
                            logging.error("Error getting event selectors - %s" % e.response["Error"]["Code"])
                        except KeyError:
                            logging.error("Error no event selectors")
                        else:                        
                            for selector in event_selectors:
                                if selector["ReadWriteType"] == "All" or selector["ReadWriteType"] == "ReadOnly":
                                    for resources in selector["DataResources"]:
                                        if resources["Type"] == "AWS::S3::Object":
                                            results["affected"].append(trail_name)
        
        if results["affected"]:
            results["analysis"] = "The affected trails have S3 Object-Level logging for read events enabled."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No trails were found with S3 Object-Level Logging enabled."
            results["affected"].append(self.account_id)
            results["pass_fail"] = "FAIL"

        if not [ i for i in self.trails.values() if i ]:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"
            results["affected"].append(self.account_id)

        return results
