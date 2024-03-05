import boto3
import json
import re
import logging

from utils.utils import get_account_id

class s3(object):

    def __init__(self, session):
        self.session = session
        self.client = self.get_client()
        self.buckets = self.list_buckets()
        self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.s3_1() ]
        findings += [ self.s3_2() ]
        findings += [ self.s3_3() ]
        findings += [ self.s3_4() ]
        findings += [ self.s3_5() ]
        findings += [ self.s3_6() ]
        findings += [ self.s3_7() ]
        findings += [ self.s3_8() ]
        findings += [ self.s3_9() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.s3_1() ]
        findings += [ self.s3_2() ]
        findings += [ self.s3_3() ]
        findings += [ self.s3_4() ]
        findings += [ self.s3_5() ]
        return findings

    def list_buckets(self):
        # returns list of s3 buckets names
        logging.info("Getting Bucket List")
        try:
            return [ bucket["Name"] for bucket in self.client.list_buckets()["Buckets"] ]
        except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting bucket list - %s" % e.response["Error"]["Code"])

    
    def get_client(self):
        # returns boto3 s3 client
        return self.session.client('s3')

    def s3_1(self):
        # Ensure all S3 buckets employ encryption-at-rest (Manual)

        results = {
            "id" : "s3_1",
            "ref" : "2.1.1",
            "compliance" : "cis",
            "level" : 2,
            "service" : "s3",
            "name" : "Ensure all S3 buckets employ encryption-at-rest (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Amazon S3 provides a variety of no, or low, cost encryption options to protect data at rest. Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.",
            "remediation" : "Ensure all S3 buckets employ encryption-at-rest. S3 bucket encryption only applies to objects as they are placed in the bucket. Enabling S3 bucket encryption does not encrypt objects previously stored within the bucket.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    encryption = self.client.get_bucket_encryption(Bucket=bucket)    
                except boto3.exceptions.botocore.exceptions.ClientError:
                    results["affected"].append(bucket)

            if results["affected"]:
                results["analysis"] = "The affected buckets do not have server side encryption enabled."
                results["pass_fail"] = "FAIL"
            else:
                results["analysis"] = "All buckets have server side encryption enabled."
                results["pass_fail"] = "PASS"
                results["affected"].append(self.account_id)

            return results
    
    def s3_2(self):
        # Ensure S3 Bucket Policy is set to deny HTTP requests (Manual)

        results = {
            "id" : "s3_2",
            "ref" : "2.1.2",
            "compliance" : "cis",
            "level" : 2,
            "service" : "s3",
            "name" : "Ensure S3 Bucket Policy is set to deny HTTP requests (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "At the Amazon S3 bucket level, you can configure permissions through a bucket policy making the objects accessible only through HTTPS. By default, Amazon S3 allows both HTTP and HTTPS requests. To achieve only allowing access to Amazon S3 objects through HTTPS you also have to explicitly deny access to HTTP requests. Bucket policies that allow HTTPS requests without explicitly denying HTTP requests will not comply with this recommendation.",
            "remediation" : "Enforce HTTPS requests for all buckets within your account",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        passing_buckets = []
        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    policy = json.loads(self.client.get_bucket_policy(Bucket=bucket)["Policy"])
                # botocore.exceptions.ClientError: An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist
                except boto3.exceptions.botocore.exceptions.ClientError:
                    # no bucket policy exists
                    pass
                else:
                    statements = policy["Statement"]
                    for statement in statements:
                        try:
                            bool_secure_transport = statement["Condition"]["Bool"]["aws:SecureTransport"]
                        except KeyError:
                            pass
                        else:
                            effect = statement["Effect"]
                            action = statement["Action"]
                            resources = statement["Resource"]
                            if bool_secure_transport == "false":
                                if effect == "Deny":
                                    if action == "s3:GetObject" or action == "s3:*":
                                        for resource in resources:
                                            if re.match(r"arn:aws:s3*|\*", resource):
                                                passing_buckets.append(bucket)

            results["affected"] = [ i for i in self.buckets if i not in passing_buckets ]
        
        if results["affected"]:
            results["analysis"] = "The affected buckets do enforce HTTPS only."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All buckets enforce HTTPS requests."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def s3_3(self):
        # Ensure MFA Delete is enable on S3 buckets (Automated)

        results = {
            "id" : "s3_3",
            "ref" : "2.1.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure MFA Delete is enable on S3 buckets (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication. Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
            "remediation" : "Configure MFA delete on all S3 buckets within your account.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        passing_buckets = []
        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    bucket_versioning = self.client.get_bucket_versioning(Bucket=bucket)
                    if bucket_versioning["Status"] == "Enabled":
                        if bucket_versioning["MfaDelete"] == "Enabled": # need testing with mfadelete enabled bucket
                            passing_buckets.append(bucket)
                except KeyError:
                    pass
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting bucket versioning - %s" % e.response["Error"]["Code"])
                
            results["affected"] = [i for i in self.buckets if i not in passing_buckets]
            
        if results["affected"]:
            results["analysis"] = "The affected buckets do not have MFA Delete enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All buckets have MFA Delete Enabled."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
    
        return results


    def s3_4(self):
        # Ensure all data in Amazon S3 has been discovered, classified and secured when required. (Manual)

        results = {
            "id" : "s3_4",
            "ref" : "2.1.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure all data in Amazon S3 has been discovered classified and secured when required (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Amazon S3 buckets can contain sensitive data, that for security purposes should be discovered, monitored, classified and protected. Macie along with other 3rd party tools can automatically provide an inventory of Amazon S3 buckets. Using a Cloud service or 3rd Party software to continuously monitor and automate the process of data discovery and classification for S3 buckets using machine learning and pattern matching is a strong defense in protecting that information. Amazon Macie is a fully managed data security and data privacy service that uses machine learning and pattern matching to discover and protect your sensitive data in AWS. ",
            "remediation" : "Enable AWS Macie",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        #client = boto3.client('macie2', region_name="eu-west-2")
        logging.info(results["name"])

        results["analysis"] = "Manual Check"
        results["pass_fail"] = "INFO"
        results["affected"].append(self.account_id)

        return results

    def s3_5(self):
        # Ensure that S3 Buckets are configured with 'Block public access (bucket settings)' (Automated)

        results = {
            "id" : "s3_5",
            "ref" : "2.1.5",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure that S3 Buckets are configured with Block public access (bucket settings) (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Amazon S3 provides Block public access (bucket settings) and Block public access (account settings) to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principal with sufficient S3 permissions can enable public access at the bucket and/or object level. While enabled, Block public access (bucket settings) prevents an individual bucket, and its contained objects, from becoming publicly accessible. Similarly, Block public access (account settings) prevents all buckets, and contained objects, from becoming publicly accessible across the entire account. Amazon S3 Block public access (bucket settings) prevents the accidental or malicious public exposure of data contained within the respective bucket(s). Amazon S3 Block public access (account settings) prevents the accidental or malicious public exposure of data contained within all buckets of the respective AWS account. Whether blocking public access to all or some buckets is an organizational decision that should be based on data sensitivity, least privilege, and use case.",
            "remediation" : "Ensure that S3 Buckets are configured with Block public access",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        passing_buckets = []      
        
        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    public_access_block_configuration = self.client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
                except boto3.exceptions.botocore.exceptions.ClientError:
                    # no public access block configuration exists
                    pass
                else:
                    if public_access_block_configuration["BlockPublicAcls"] == True:
                        if public_access_block_configuration["IgnorePublicAcls"] == True:
                            if public_access_block_configuration["BlockPublicPolicy"] == True:
                                if public_access_block_configuration["RestrictPublicBuckets"] == True:
                                    passing_buckets.append(bucket)

            results["affected"] = [i for i in self.buckets if i not in passing_buckets]
        
        if results["affected"]:
            results["analysis"] = "The affected buckets do not block public access."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Buckets block public access."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results

    def s3_6(self):
        # Check if S3 buckets have object versioning enabled

        results = {
            "id" : "s3_6",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "s3",
            "name" : "S3 buckets without object versioning enabled",
            "affected": [],
            "analysis" : "",
            "description" : "The AWS account under review contains S3 buckets that do not have versioning enabled. By preserving a version history of objects in your S3 bucket, versioning can be used for data protection and retention scenarios such as recovering objects that have been accidentally/intentionally deleted or overwritten. Once you enable Versioning for a bucket, Amazon S3 preserves existing objects anytime you perform a PUT, POST, COPY, or DELETE operation on them. By default, GET requests will retrieve the most recently written version. Older versions of an overwritten or deleted object can be retrieved by specifying a version in the request.",
            "remediation" : "Consider enabling versioning for at least buckets that contain important and sensitive information, this is enabled at the bucket level and can be done via the AWS web console. Note: an additional cost will be incurred for the extra storage space versioning will inevitably use. More Information: https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    bucket_versioning_status = self.client.get_bucket_versioning(Bucket=bucket)["Status"]
                #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
                except KeyError:
                    # no public access block configuration exists
                    results["affected"].append(bucket)
                    pass
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting bucket versioning - %s" % e.response["Error"]["Code"])
                else:
                    if bucket_versioning_status == "Suspended":
                        results["affected"].append(bucket)
        
        if results["affected"]:
            results["analysis"] = "The affected buckets do not have Object Versioning enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Buckets have Object Versioning enabled.."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results

    def s3_7(self):
        # S3 buckets grant public access via ACL

        results = {
            "id" : "s3_7",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "s3",
            "name" : "S3 Buckets Grant Public Access Via ACL",
            "affected": [],
            "analysis" : "",
            "description" : "The affected S3 buckets have an Access Control List (ACL) configured which grant public acces to objects. Either list or read access. Public S3 buckets can be accessed without authentication and increase teh risk of senstivie data being exposed to unauthorised network bearers.",
            "remediation" : "Review the affected buckets and confirm that public access to objects is required.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        passing_buckets = []      
        
        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    public_access_block_configuration = self.client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
                except boto3.exceptions.botocore.exceptions.ClientError:
                    # no public access block configuration exists
                    pass
                else:
                    if public_access_block_configuration["BlockPublicAcls"] == True:
                        if public_access_block_configuration["IgnorePublicAcls"] == True:
                            if public_access_block_configuration["BlockPublicPolicy"] == True:
                                if public_access_block_configuration["RestrictPublicBuckets"] == True:
                                    passing_buckets.append(bucket)

            public_buckets = [i for i in self.buckets if i not in passing_buckets]
            for bucket in public_buckets:
                try:
                    grants = self.client.get_bucket_acl(Bucket=bucket)["Grants"]
                except boto3.exceptions.botocore.exceptions.ClientError:
                    logging.error("Error getting bucket acl - %s" % e.response["Error"]["Code"])
                else:
                    for grant in grants:
                        if grant["Grantee"]["Type"] == "Group":
                            if grant["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AllUsers" or grant["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                                if bucket not in results["affected"]:
                                    results["affected"].append(bucket)
        
        if results["affected"]:
            results["analysis"] = "The affected buckets grant public access via an ACL. Review the buckets to ensure public access is intended."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No buckets were found which grant public access via an ACL."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results

    def s3_8(self):
        # S3 buckets grant public access via Policy

        results = {
            "id" : "s3_8",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "s3",
            "name" : "S3 Buckets Grant Public Access Via Policy",
            "affected": [],
            "analysis" : "",
            "description" : "The affected S3 buckets have a bucket policy configured which grants public acces to objects, possibly for S3 static website hosting. Public S3 buckets can be accessed without authentication and increase teh risk of senstivie data being exposed to unauthorised network bearers.",
            "remediation" : "Review the affected buckets and confirm that public access to objects is required. and update the bucket policy accordingly",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        passing_buckets = []      
        
        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    public_access_block_configuration = self.client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                    #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
                except boto3.exceptions.botocore.exceptions.ClientError:
                    # no public access block configuration exists
                    pass
                else:
                    if public_access_block_configuration["BlockPublicAcls"] == True:
                        if public_access_block_configuration["IgnorePublicAcls"] == True:
                            if public_access_block_configuration["BlockPublicPolicy"] == True:
                                if public_access_block_configuration["RestrictPublicBuckets"] == True:
                                    passing_buckets.append(bucket)

            public_buckets = [i for i in self.buckets if i not in passing_buckets]
            for bucket in public_buckets:
                try:
                    policy = self.client.get_bucket_policy(Bucket=bucket)["Policy"]
                except boto3.exceptions.botocore.exceptions.ClientError:
                    pass
                    # no bucket policy
                else:
                    policy_dict = json.loads(policy)
                    try:
                        for statement in policy_dict["Statement"]:
                            if statement["Effect"] == "Allow":
                                if statement["Principal"] == "*":
                                    if bucket not in results["affected"]:
                                        results["affected"].append(bucket)
                    except KeyError:
                        logging.error("Error getting parsing bucket policy - %s" % e.response["Error"]["Code"])

        
        if results["affected"]:
            results["analysis"] = "The affected buckets grant public access via a Bucket Policy. Review the buckets to ensure public access is intended."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No buckets were found which grant public access via an ACL."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results

    def s3_8(self):
        # S3 buckets grant public access via Policy

        results = {
            "id" : "s3_8",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "s3",
            "name" : "S3 Buckets Grant Public Access Via Policy",
            "affected": [],
            "analysis" : "",
            "description" : "The affected S3 buckets have a bucket policy configured which grants public acces to objects, possibly for S3 static website hosting. Public S3 buckets can be accessed without authentication and increase teh risk of senstivie data being exposed to unauthorised network bearers.",
            "remediation" : "Review the affected buckets and confirm that public access to objects is required. and update the bucket policy accordingly",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        passing_buckets = []      
        
        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    public_access_block_configuration = self.client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                    #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
                except boto3.exceptions.botocore.exceptions.ClientError:
                    # no public access block configuration exists
                    pass
                else:
                    if public_access_block_configuration["BlockPublicAcls"] == True:
                        if public_access_block_configuration["IgnorePublicAcls"] == True:
                            if public_access_block_configuration["BlockPublicPolicy"] == True:
                                if public_access_block_configuration["RestrictPublicBuckets"] == True:
                                    passing_buckets.append(bucket)

            public_buckets = [i for i in self.buckets if i not in passing_buckets]
            for bucket in public_buckets:
                try:
                    policy = self.client.get_bucket_policy(Bucket=bucket)["Policy"]
                except boto3.exceptions.botocore.exceptions.ClientError:
                    pass
                    # no bucket policy
                else:
                    policy_dict = json.loads(policy)
                    try:
                        for statement in policy_dict["Statement"]:
                            if statement["Effect"] == "Allow":
                                if statement["Principal"] == "*":
                                    if bucket not in results["affected"]:
                                        results["affected"].append(bucket)
                    except KeyError:
                        logging.error("Error getting parsing bucket policy - %s" % e.response["Error"]["Code"])

        
        if results["affected"]:
            results["analysis"] = "The affected buckets grant public access via a Bucket Policy. Review the buckets to ensure public access is intended."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No buckets were found which grant public access via an ACL."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results

    def s3_9(self):
        # S3 buckets with bucket Policy Attached

        results = {
            "id" : "s3_9",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "s3",
            "name" : "S3 Buckets with Bucket Policy Attached",
            "affected": [],
            "analysis" : "",
            "description" : "The affected S3 buckets have a bucket policy configured",
            "remediation" : "Review the affected buckets to ensure the bucket policy follows the principle of least privilege.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        passing_buckets = []      
        
        if self.buckets != None:
            for bucket in self.buckets:
                try:
                    public_access_block_configuration = self.client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                    #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
                except boto3.exceptions.botocore.exceptions.ClientError:
                    # no public access block configuration exists
                    pass
                else:
                    if public_access_block_configuration["BlockPublicAcls"] == True:
                        if public_access_block_configuration["IgnorePublicAcls"] == True:
                            if public_access_block_configuration["BlockPublicPolicy"] == True:
                                if public_access_block_configuration["RestrictPublicBuckets"] == True:
                                    passing_buckets.append(bucket)

            public_buckets = [i for i in self.buckets if i not in passing_buckets]
            for bucket in public_buckets:
                try:
                    policy = self.client.get_bucket_policy(Bucket=bucket)["Policy"]
                except boto3.exceptions.botocore.exceptions.ClientError:
                    pass
                    # no bucket policy
                else:
                    policy_dict = json.loads(policy)
                    if bucket not in results["affected"]:
                        results["affected"].append(bucket)
        
        if results["affected"]:
            results["analysis"] = "The affected buckets have a bucket policy attached."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No buckets were found which use a bucket policy"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results
