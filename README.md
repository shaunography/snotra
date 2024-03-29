# Snotra
Snotra (pronounced "snow-trah” ) is a pure Python Cloud (AWS) Auditing Tool it uses boto3 to audit your AWS account against a list of common issues and compliance standards including the CIS benchmark. Snotra produces a results.json file that can be easily incorporated into existing reporting workflows.

## requirements
* Python3
* boto3

## permissions
The following AWS Managed Policies can be attached to the principal in order to grant the access keys the necessary permissions:
* ReadOnlyAccess
* ViewOnlyAccess
* SecurityAudit

## docker
from the cloned repo directory, run:

`docker build -t snotra .`

`docker run --rm -ti -v ~/.aws:/root/.aws/ snotra`

## usage
run full audit using default aws profile

`$ python3 snotra.py --results-dir ./snotra/`

run full audit with named profile

`$ python3 snotra.py --results-dir ./snotra/ --profile prod_web`

run CIS only audit with named profile

`$ python3 snotra.py --results-dir ./snotra/ --profile prod_web --cis`

## Lambda
It is also possible to deploy Snotra as a Lambda Function, see the following blog post for more info.

https://www.shaunography.com/snotra-lambda.html


## checks
### CIS Benchmark v1.5.0
Snotra currently completes all checks included in the latest CIS Benchmark. Although Snotra reports on them, a few of the checks can not be completed programatically - these are marked accordingly.

### other
Additional checks beyond the CIS benchmark

* unused security groups (ec2)
* guardduty not enabled in all regions (guardduty)
* unused elastic IPs (ec2)
* cloudwatch alarms with no actions configured (cloudwatch)
* efs with no access policy, grants access to all clients (efs)
* public EBS snapshots (ec2)
* public EC2 AMIs (ec2)
* public SNS topics (sns)
* security groups allow database traffic from 0.0.0.0/0 (ec2)
* network acls allow database traffic from 0.0.0.0/0 (ec2)
* default network acls allow all traffic (ec2)
* custom network acls allow all traffic (ec2)
* security hub not enabled (securityhub)
* security hub does not have autoenablecontrols enabled (securityhub)
* unused IAM groups (iam)
* unused network interfaces (ec2)
* instances older than 365 days (ec2)
* ensure EC2 instance metadata service version 2 (IMDSv2) is enabled and required (ec2)
* instances not managed by AWS systems manager (ec2)
* unencrypted ebs volumes (ec2)
* unencrypted ebs snapshots (ec2)
* old ebs snapshots (ec2)
* cross-account assumerole policy lacks external ID (iam)
* groups granting admin access (iam)
* group name does not indicate admin access (iam)
* default vpcs in use (ec2)
* internet facing load balancers (elb)
* internet facing load balancers using unencrypted http listeners (elb)
* ELB listeners with weak TLS configuration (elb)
* ALBs not configured to drop invalid headers (elb)
* desync mitigation mode not enabled (elb)
* S3 buckets without object versioning enabled (s3)
* ECR Image Scan on Push is not Enabled (ecr)
* RDS Instances Do Not Have Deletion Protection Enabled (rds)
* Unencrypted SNS Topics (sns)
* Domain Does Not Have Domain Transfer Lock Set (route53)
* ACM Certificate with Transparency Logging Set to Disabled (acm)
* Expired ACM Certificates (acm)
* Lack of ELB Access Logging (elb)
* Load Balancer Deletion Protection not Configured (elb)
* Group with inline policies (iam)
* High Risk Guard Duty Findings (guardduty)
* Overly Permisions Cross Account Assume Role (IAM)
* Incorrect policy used to attempt to enforce MFA (IAM)
* Overly permissive VPC Endpoint (EC2)
* Domain without auto renew enabled (route53)
* AmazonEC2RoleforSSM Managed Policy In Use (iam)
* Reource Explorer Indexes in use (resourceexplorer)
* CodeBuild Project Environment Variabled (Check for secrets) (codebuild)
* EC2 instance UserData (Check for secrets) (ec2)
* CloudFormation stack output (Check for secrets) (cloudformation)
* SSM parameter store parameters (check for secrets) (ssm)
* ecr repositories with no lifecycle policy (ecr)
* Overly Privileged Cross Account Assume Role Trust Policy GitHub OIDC (IAM)
* Overly permissions cross service trust role (IAM)
* athena work groups not using encryption (athena)
* EC2 instances with pubic IPs (ec2)
* EC2 instances without detailed monitoring enabled (ec2)
* S3 buckets grant public access via ACL (s3)
* S3 buckets grant public access via policy (s3)
* S3 buckets with bucket policy attacched (s3)
* Ensure Access Keys are protected with MFA (iam)
* Users with Admin access via directly attached policy (iam)
* stopped ec2 instances (ec2)
* Ensure Tags Do Not Contain Sensitive or PII Data (resourcegroupstaggingapi)
* A list of all resources (ARNs) in the account (resourcegroupstaggingapi)
* api gateways in use (apigateway)
* api gateways using lambda authorizers (apigateways)

## results JSON
The results JSON file that Snotra produces is in the following format:
```
{
    "account" : account_id,                     # account ID e.g. 123456789123
    "user" : user_arn,                          # ARN of user used to run test e.g. arn:aws:iam::123456789123:user/shaun
    "datetime" : datetime.today(),              # datetime of scan e.g. 2021-09-11 13:14:34.562040
    "findings" : [
        {                                       # each check function returns a results dictionary in this format
            "id": id,                           # finding ID e.g "iam_3" (string)
            "ref": ref,                         # finding reference CIS etc e.g "2.3.1" (string)
            "compliance": compliance,           # is the finding from a compliance standard e.g. "cis" (string)
            "level": level,                     # CIS level e.g 1 (int)
            "service": service,                 # AWS service e.g "iam" (string)
            "name": name,                       # finding name e.g. "Ensure that encryption is enabled for RDS Instances" (string)
            "affected": affected,               # affected resources e.g. ["eu-west-2", "eu-west-1"] (list)
            "analysis": analysis,               # technical analysis e.g. "AWS config is not enabled in eu-west-1" (string)
            "description": description,         # description of issue e.g. "AWS Config is a web service that performs ..." (string)
            "remediation": remediation,         # remediation advice e.g. "enable AWS Config in all regions" (string)
            "impact": impact,                   # impact rating (high|medium|low|info) e.g. "medium" (string)
            "probability": probability,         # probably rating (high|medium|low|info) e.g. "low" (string)
            "cvss_vector": cvss_vector,         # CVSS v3 vector e.g "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" (string)
            "cvss_score": cvss_score,           # CVSS v3 score e.g. "4.8" (string)
            "pass_fail": pass_fail              # finding results (pass|fail) e.g. "FAIL" (string)
        },
        ...
    ]
}
```
## reporting tools
* [snotra_to_table](https://github.com/shaunography/snotra_to_table) - Converts Snotra results JSON file into a simple CSV table for pasting into reports.
* [snotra_to_md](https://github.com/shaunography/snotra_to_md) - Converts Snotra results JSON file to a simple Mark Down file.

## contributions
### code
Pull requests, bug reports and enhancement suggestions are more than welcome.

### checks
All checks are a function/method of the relevent class and are in the following format:

```
    def service_n(self):
        # name of check
        
        results = {
            "id" : "service_n",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "service",
            "name" : "name of check",
            "affected": [],
            "analysis" : "",
            "description" : "this is a check template",
            "remediation" : "hack all the things",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        # actual check logic here

        return results
```

All methods contain the results dictionary object, print the name of the check on start up and retun the results dict after completing the check logic and populating it (affected, analysis and pass_fail) with the results of the check. 

### donations
If you appreciate my work and gain value from using Snotra feel free to donate some sats at https://coinos.io/shaunwebber
