import boto3

from utils.utils import describe_regions

class cloudwatch(object):

    def __init__(self):
        self.regions = describe_regions()

    def run(self):
        findings = []
        findings += [ self.cloudwatch_1() ]
        findings += [ self.cloudwatch_2() ]
        findings += [ self.cloudwatch_3() ]
        findings += [ self.cloudwatch_4() ]
        findings += [ self.cloudwatch_5() ]
        findings += [ self.cloudwatch_6() ]
        findings += [ self.cloudwatch_7() ]
        findings += [ self.cloudwatch_8() ]
        findings += [ self.cloudwatch_9() ]
        findings += [ self.cloudwatch_10() ]
        findings += [ self.cloudwatch_11() ]
        findings += [ self.cloudwatch_12() ]
        findings += [ self.cloudwatch_13() ]
        findings += [ self.cloudwatch_14() ]
        findings += [ self.cloudwatch_15() ]
        return findings
        
    def cloudwatch_1(self):
        # Ensure a log metric filter and alarm exist for unauthorized API calls (Automated)

        results = {
            "id" : "cloudwatch_",
            "ref" : "4.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for unauthorized API calls",
            "affected": "",
            "analysis" : "No log metric filter and alarm for unauthorized API calls could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for unauthorized API calls. Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity.",
            "remediation" : "Create a log metric filter and alarm for unauthorized API calls in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x

        print("running check: cloudwatch_1")
        
        passing_metrics = []

        ## What a mess, could probably be moved into a seperate function to be shared with the other metric/alarm checks
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") || ($.sourceIPAddress!="delivery.logs.amazonaws.com") || ($.eventName!="HeadBucket") }
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*UnauthorizedOperation.*)(?:.*AccessDenied.*)(?:.*"delivery.logs.amazonaws.com".*)(?:.*"HeadBucket".*)'
                                                if re.match(regex, metric_filter_pattern):

                                                    # check alarm exists for filter
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for unauthorized API calls: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results


    def cloudwatch_2(self):
        # Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Automated)

        results = {
            "id" : "cloudwatch_2",
            "ref" : "4.2",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA",
            "affected": "",
            "analysis" : "No log metric filter and alarm for Management Console sign-in without MFA could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for console logins that are not protected by multi-factor authentication (MFA). Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA.",
            "remediation" : "Create a log metric filter and alarm for Management Console sign-in without MFA in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x

        print("running check: cloudwatch_2")
        
        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }
                                                metric_filter_pattern = filter["filterPattern"]

                                                regex = '(?:.*"ConsoleLogin".*)(?:.*MFAUsed.*Yes.*)(?:.*"IAMUser".*)(?:.*"Success".*)'
                                                if re.match(regex, metric_filter_pattern):

                                                    # check alarm exists for filter
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for Management Console sign-in without MFA: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
        
        
    def cloudwatch_3(self):
        # Ensure a log metric filter and alarm exist for usage of 'root' account (Automated)

        results = {
            "id" : "cloudwatch_3",
            "ref" : "4.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for usage of root account",
            "affected": "",
            "analysis" : "No log metric filter and alarm for usage of 'root' account could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for 'root' login attempts. Monitoring for 'root' account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it.",
            "remediation" : "Create a log metric filter and alarm for usage of root account in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x

        print("running check: cloudwatch_3")
        
        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
                                                metric_filter_pattern = filter["filterPattern"]

                                                regex = '(?:.*userIdentity.type\s=\s"Root".*)(?:.*NOT\sEXISTS.*)(?:.*eventType\s!=\s"AwsServiceEvent".*)'
                                                if re.match(regex, metric_filter_pattern):
                                                            
                                                    # check alarm exists for filter
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for usage of 'root' account: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    def cloudwatch_4(self):
        # Ensure a log metric filter and alarm exist for IAM policy changes (Automated)

        results = {
            "id" : "cloudwatch_4",
            "ref" : "4.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for IAM policy changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for IAM policy changes could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established changes made to Identity and Access Management (IAM) policies. Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact.",
            "remediation" : "Create a log metric filter and alarm for IAM policy changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_4")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # {($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = "(?:.*DeleteGroupPolicy.*)(?:.*DeleteRolePolicy.*)(?:.*DeleteUserPolicy.*)(?:.*PutGroupPolicy.*)(?:.*PutRolePolicy.*)(?:.*PutUserPolicy.*)(?:.*CreatePolicy.*)(?:.*DeletePolicy.*)(?:.*CreatePolicyVersion.*)(?:.*DeletePolicyVersion.*)(?:.*AttachRolePolicy.*)(?:.*DetachRolePolicy.*)(?:.*AttachUserPolicy.*)(?:.*DetachUserPolicy.*)(?:.*AttachGroupPolicy.*)(?:.*DetachGroupPolicy.*)"
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for for IAM policy changes: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    def cloudwatch_5(self):
        # Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Automated)

        results = {
            "id" : "cloudwatch_5",
            "ref" : "4.5",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for CloudTrail configuration changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for CloudTrail configuration changes could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail's configurations. Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account.",
            "remediation" : "Create a log metric filter and alarm for CloudTrail configuration changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_5")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = "(?:.*CreateTrail.*)(?:.*UpdateTrail.*)(?:.*DeleteTrail.*)(?:.*StartLogging.*)(?:.*StopLogging.*)"
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for CloudTrail configuration changes: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    def cloudwatch_6(self):
        # Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Automated)

        results = {
            "id" : "cloudwatch_6",
            "ref" : "4.6",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures",
            "affected": "",
            "analysis" : "No log metric filter and alarm for AWS Management Console authentication failures could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for failed console authentication attempts. Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation.",
            "remediation" : "Create a log metric filter and alarm for AWS Management Console authentication failures in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_6")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*eventName\s\=\sConsoleLogin.*)(?:.*errorMessage\s\=\s"Failed\sauthentication".*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for AWS Management Console authentication failures: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    def cloudwatch_7(self):
        # Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Automated)

        results = {
            "id" : "cloudwatch_7",
            "ref" : "4.7",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs",
            "affected": "",
            "analysis" : "No log metric filter and alarm for disabling or scheduled deletion of customer created CMKs could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for customer created CMKs which have changed state to disabled or scheduled deletion. Data encrypted with disabled or deleted keys will no longer be accessible.",
            "remediation" : "Create a log metric filter and alarm for disabling or scheduled deletion of customer created CMKs in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_7")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*kms.amazonaws.com.*)(?:.*DisableKey.*)(?:.*ScheduleKeyDeletion.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for disabling or scheduled deletion of customer created CMKs: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results

    def cloudwatch_8(self):
        # Ensure a log metric filter and alarm exist for S3 bucket policy changes (Automated)

        results = {
            "id" : "cloudwatch_8",
            "ref" : "4.8",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for S3 bucket policy changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for S3 bucket policy changes could be found",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for changes to S3 bucket policies. Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets.",
            "remediation" : "Create a log metric filter and alarm for S3 bucket policy changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_8")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*s3.amazonaws.com.*)(?:.*PutBucketAcl.*)(?:.*PutBucketPolicy.*)(?:.*PutBucketCors.*)(?:.*PutBucketLifecycle.*)(?:.*PutBucketReplication.*)(?:.*DeleteBucketPolicy.*)(?:.*DeleteBucketCors.*)(?:.*DeleteBucketLifecycle.*)(?:.*DeleteBucketReplication.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for S3 bucket policy changes: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    
    def cloudwatch_9(self):
        # Ensure a log metric filter and alarm exist for AWS Config configuration changes (Automated)

        results = {
            "id" : "cis48",
            "ref" : "4.9",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for AWS Config configuration changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for AWS Config configuration changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail's configurations. Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account.",
            "remediation" : "Create a log metric filter and alarm for AWS Config configuration changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_9")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*config.amazonaws.com.*)(?:.*StopConfigurationRecorder.*)(?:.*DeleteDeliveryChannel.*)(?:.*PutDeliveryChannel.*)(?:.*PutConfigurationRecorder.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for AWS Config configuration changes: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results


    def cloudwatch_10(self):
        # Ensure a log metric filter and alarm exist for security group changes (Automated)

        results = {
            "id" : "cis49",
            "ref" : "4.10",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for security group changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for security group changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC. It is recommended that a metric filter and alarm be established for detecting changes to Security Groups. Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.",
            "remediation" : "Create a log metric filter and alarm for security group changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_10")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*AuthorizeSecurityGroupIngress.*)(?:.*AuthorizeSecurityGroupEgress.*)(?:.*RevokeSecurityGroupIngress.*)(?:.*RevokeSecurityGroupEgress.*)(?:.*CreateSecurityGroup.*)(?:.*DeleteSecurityGroup.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for security group changes: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    
    def cloudwatch_11(self):
        # Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Automated)

        results = {
            "id" : "cloudwatch_11",
            "ref" : "4.11",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)",
            "affected": "",
            "analysis" : "No log metric filter and alarm for changes to Network Access Control Lists (NACL)",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC. It is recommended that a metric filter and alarm be established for detecting changes to Security Groups. Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.",
            "remediation" : "Create a log metric filter and alarm for changes to Network Access Control Lists (NACL) in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_11")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*CreateNetworkAcl.*)(?:.*CreateNetworkAclEntry.*)(?:.*DeleteNetworkAcl.*)(?:.*DeleteNetworkAclEntry.*)(?:.*ReplaceNetworkAclEntry.*)(?:.*ReplaceNetworkAclAssociation.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for changes to Network Access Control Lists (NACL): {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    def cloudwatch_12(self):
        # Ensure a log metric filter and alarm exist for changes to network gateways (Automated)

        results = {
            "id" : "cis51",
            "ref" : "4.12",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for changes to network gateways",
            "affected": "",
            "analysis" : "No log metric filter and alarm for changes to network gateways",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC. It is recommended that a metric filter and alarm be established for detecting changes to Security Groups. Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.",
            "remediation" : "Create a log metric filter and alarm for changes to network gateways in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_11")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*CreateCustomerGateway.*)(?:.*DeleteCustomerGateway.*)(?:.*AttachInternetGateway.*)(?:.*CreateInternetGateway.*)(?:.*DeleteInternetGateway.*)(?:.*DetachInternetGateway.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for changes to network gateways: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    def cloudwatch_13(self):
        # Ensure a log metric filter and alarm exist for route table changes (Automated)

        results = {
            "id" : "cloudwatch_13",
            "ref" : "4.13",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for route table changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for route table changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables. Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path. ",
            "remediation" : "Create a log metric filter and alarm for route table changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_13")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*CreateRoute.*)(?:.*CreateRouteTable.*)(?:.*ReplaceRoute.*)(?:.*ReplaceRouteTableAssociation.*)(?:.*DeleteRouteTable.*)(?:.*DeleteRoute.*)(?:.*DisassociateRouteTable.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for route table changes: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    def cloudwatch_14(self):
        # Ensure a log metric filter and alarm exist for VPC changes (Automated)

        results = {
            "id" : "cloudwatch_14",
            "ref" : "4.14",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for VPC changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for VPC changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is possible to have more than 1 VPC within an account, in addition it is also possible to create a peer connection between 2 VPCs enabling network traffic to route between VPCs. It is recommended that a metric filter and alarm be established for changes made to VPCs. Monitoring changes to VPC will help ensure VPC traffic flow is not getting impacted.",
            "remediation" : "Create a log metric filter and alarm for route table changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_14")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*CreateVpc.*)(?:.*DeleteVpc.*)(?:.*ModifyVpcAttribute.*)(?:.*AcceptVpcPeeringConnection.*)(?:.*CreateVpcPeeringConnection.*)(?:.*DeleteVpcPeeringConnection.*)(?:.*RejectVpcPeeringConnection.*)(?:.*AttachClassicLinkVpc.*)(?:.*DetachClassicLinkVpc.*)(?:.*DisableVpcClassicLink.*)(?:.*EnableVpcClassicLink.*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for VPC changes: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results
    
    def cloudwatch_15(self):
        # Ensure a log metric filter and alarm exist for AWS Organizations changes (Automated)

        results = {
            "id" : "cloudwatch_15",
            "ref" : "4.15",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudwatch",
            "name" : "Ensure a log metric filter and alarm exist for AWS Organizations changes",
            "affected": "",
            "analysis" : "No log metric filter and alarm for AWS Organizations changes",
            "description" : "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for AWS Organizations changes made in the master AWS Account. Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches. This monitoring technique helps you to ensure that any unexpected changes performed within your AWS Organizations can be investigated and any unwanted changes can be rolled back.",
            "remediation" : "Create a log metric filter and alarm for route table changes in CloudWatch Logs",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "FAIL"
        }

        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/include/check3x
        
        print("running check: cloudwatch_15")

        passing_metrics = []
     
        for region in self.regions:
            client = boto3.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    try:
                        cloudwatch_logs_log_group_arn = trail["CloudWatchLogsLogGroupArn"]
                        cloudtrail_log_group_name = cloudwatch_logs_log_group_arn.split(":")[6]
                        #cloudtrail_log_group_region = cloudwatch_logs_log_group_arn.split(":")[3]
                        #cloudtrail_log_group_account = cloudwatch_logs_log_group_arn.split(":")[4]
                    except KeyError:
                        # trail not integrated with cloudwatch logs
                        pass
                    else:

                        # check if trail is multi region
                        if trail["IsMultiRegionTrail"] == True:
                            trail_name = trail["Name"]

                            # check trail is enabled
                            if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                                
                                # check logging of all events
                                event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"][0]
                                if event_selectors["ReadWriteType"] == "All":

                                    # check management event logging
                                    if event_selectors["IncludeManagementEvents"] == True:
                                        
                                        # get cloud watch metrics
                                        logs_client = boto3.client('logs', region_name=region)
                                        try:
                                            metric_filters = logs_client.describe_metric_filters(logGroupName=cloudtrail_log_group_name)["metricFilters"]
                                        except boto3.exceptions.botocore.exceptions.ClientError:
                                            results["analysis"] = "could not access CloudWatch Logs Log Group: {}".format(cloudwatch_logs_log_group_arn)
                                            results["pass_fail"] = "INFO"

                                        else:
                                            for filter in metric_filters:

                                                # check desired filter exists
                                                metric_filter_name = filter["filterName"]
                                                
                                                # { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                                                metric_filter_pattern = filter["filterPattern"]
                                                regex = '(?:.*organizations.amazonaws.com.*)(?:.*"AcceptHandshake".*)(?:.*"AttachPolicy".*)(?:.*"CreateAccount".*)(?:.*"CreateOrganizationalUnit".*)(?:.*"CreatePolicy".*)(?:.*"DeclineHandshake".*)(?:.*"DeleteOrganization".*)(?:.*"DeleteOrganizationalUnit".*)(?:.*"DeletePolicy".*)(?:.*"DetachPolicy".*)(?:.*"DisablePolicyType".*)(?:.*"EnablePolicyType".*)(?:.*"InviteAccountToOrganization".*)(?:.*"LeaveOrganization".*)(?:.*"MoveAccount".*)(?:.*"RemoveAccountFromOrganization".*)(?:.*"UpdatePolicy".*)(?:.*"UpdateOrganizationalUnit".*)'
                                                if re.match(regex, metric_filter_pattern):    

                                                    # check alarm exists for filter                                                
                                                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)
                                                    metric_alarms = cloudwatch_client.describe_alarms()["MetricAlarms"]
                                                    for alarm in metric_alarms:
                                                        if alarm["MetricName"] == metric_filter_name:
                                                            sns_topic_arn =  alarm["AlarmActions"][0]
                                                            
                                                            # check SNS topic has a subcriber
                                                            sns_client = boto3.client('sns', region_name=region)
                                                            subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_topic_arn)["Subscriptions"]
                                                            if subscriptions:
                                                                passing_metrics += [metric_filter_name]

        if passing_metrics:
            results["analysis"] = "the following metric filters were found for AWS Organizations changes: {}".format(" ".join(passing_metrics))
            results["pass_fail"] = "PASS"

        return results