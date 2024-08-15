import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

class autoscaling(object):

    def __init__(self, session):
        self.regions = describe_regions(session)
        self.session = session
        self.account_id = get_account_id(session)
        self.auto_scaling_groups = self.get_auto_scaling_groups()
        self.launch_configurations = self.get_launch_configurations()

    def run(self):
        findings = []
        findings += [ self.autoscaling_1() ]
        findings += [ self.autoscaling_2() ]
        findings += [ self.autoscaling_3() ]
        findings += [ self.autoscaling_4() ]
        findings += [ self.autoscaling_5() ]
        findings += [ self.autoscaling_6() ]
        findings += [ self.autoscaling_7() ]
        return findings

    def get_auto_scaling_groups(self):
        logging.info("Getting Auto Scaling Groups")
        groups = {}
        for region in self.regions:
            client = self.session.client('autoscaling', region_name=region)
            try:
                response = client.describe_auto_scaling_groups()["AutoScalingGroups"]
                if response:
                    groups[region] = response
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting auto scaling groups - %s" % e.response["Error"]["Code"])
        return groups

    def get_launch_configurations(self):
        logging.info("Getting Launch Configurations")
        groups = {}
        for region in self.regions:
            client = self.session.client('autoscaling', region_name=region)
            try:
                response = client.describe_launch_configurations()["LaunchConfigurations"]
                if response:
                    groups[region] = response
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting launch configurations - %s" % e.response["Error"]["Code"])
        return groups

    def autoscaling_1(self):
        # Auto Scaling groups associated with a load balancer should use ELB health checks

        results = {
            "id" : "autoscaling_1",
            "ref" : "AutoScaling.1",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "autoscaling",
            "name" : "Auto Scaling groups associated with a load balancer should use ELB health checks",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon EC2 Auto Scaling group that is associated with a load balancer uses Elastic Load Balancing (ELB) health checks. The control fails if the Auto Scaling group doesn't use ELB health checks. ELB health checks help ensure that an Auto Scaling group can determine an instance's health based on additional tests provided by the load balancer. Using Elastic Load Balancing health checks also helps support the availability of applications that use EC2 Auto Scaling groups.",
            "remediation" : "To add Elastic Load Balancing health checks, see Add Elastic Load Balancing health checks in the Amazon EC2 Auto Scaling User Guide.\nMore Information\nhttps://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-elb-healthcheck.html#as-add-elb-healthcheck-console",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        types = [ "EC2", "ELB", "VPC_LATTICE" ]

        for region, auto_scaling_groups in self.auto_scaling_groups.items():
            for group in auto_scaling_groups:
                if group["LoadBalancerNames"]:
                    if group["HealthCheckType"] not in types:
                        results["affected"].append(group["AutoScalingGroupName"])

        if results["affected"]:
            results["analysis"] = "The affected Auto Scaling Groups are associated with a load balancer and do not use ELB health checks"
            results["pass_fail"] = "FAIL"
        elif self.auto_scaling_groups:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Auto Scaling Groups In Use"
            results["affected"].append(self.account_id)

        return results

    def autoscaling_2(self):
        # Amazon EC2 Auto Scaling group should cover multiple Availability Zones

        results = {
            "id" : "autoscaling_2",
            "ref" : "AutoScaling.2",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "autoscaling",
            "name" : "Amazon EC2 Auto Scaling group should cover multiple Availability Zones",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon EC2 Auto Scaling group spans at least the specified number of Availability Zones (AZs). The control fails if an Auto Scaling group doesn't span at least the specified number of AZs. Unless you provide a custom parameter value for the minimum number of AZs, Security Hub uses a default value of two AZs. An Auto Scaling group that doesn't span multiple AZs can't launch instances in another AZ to compensate if the configured single AZ becomes unavailable. However, an Auto Scaling group with a single Availability Zone may be preferred in some use cases, such as batch jobs or when inter-AZ transfer costs need to be kept to a minimum. In such cases, you can disable this control or suppress its findings. ",
            "remediation" : "To add AZs to an existing Auto Scaling group, see Add and remove Availability Zones in the Amazon EC2 Auto Scaling User Guide.\nMore Information:\nhttps://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-availability-zone.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, auto_scaling_groups in self.auto_scaling_groups.items():
            for group in auto_scaling_groups:
                if len(group["AvailabilityZones"]) < 2:
                    results["affected"].append(group["AutoScalingGroupName"])

        if results["affected"]:
            results["analysis"] = "The affected Auto Scaling Groups are not using multiple availability zones"
            results["pass_fail"] = "FAIL"
        elif self.auto_scaling_groups:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Auto Scaling Groups In Use"
            results["affected"].append(self.account_id)

        return results

    def autoscaling_3(self):
        # Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)

        results = {
            "id" : "autoscaling_3",
            "ref" : "AutoScaling.3",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "autoscaling",
            "name" : "Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether IMDSv2 is enabled on all instances launched by Amazon EC2 Auto Scaling groups. The control fails if the Instance Metadata Service (IMDS) version isn't included in the launch configuration or is configured as token optional, which is a setting that allows either IMDSv1 or IMDSv2. IMDS provides data about your instance that you can use to configure or manage the running instance. Version 2 of the IMDS adds new protections that weren't available in IMDSv1 to further safeguard your EC2 instances.",
            "remediation" : "An Auto Scaling group is associated with one launch configuration at a time. You cannot modify a launch configuration after you create it. To change the launch configuration for an Auto Scaling group, use an existing launch configuration as the basis for a new launch configuration with IMDSv2 enabled. For more information, see Configure instance metadata options for new instances in the Amazon EC2 User Guide.\nMore Information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, launch_configurations in self.launch_configurations.items():
            for configuration in launch_configurations:
                try:
                    if configuration["MetadataOptions"]["HttpTokens"] == "optional":
                        results["affected"].append(configuration["LaunchConfigurationName"])
                except KeyError:
                    results["affected"].append(configuration["LaunchConfigurationName"])

        if results["affected"]:
            results["analysis"] = "The affected launch configurations are not using version two of the metadata service"
            results["pass_fail"] = "FAIL"
        elif self.launch_configurations:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Auto Scaling Groups In Use"
            results["affected"].append(self.account_id)

        return results

    def autoscaling_4(self):
        # Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses

        results = {
            "id" : "autoscaling_4",
            "ref" : "AutoScaling.5",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "autoscaling",
            "name" : "Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Auto Scaling group's associated launch configuration assigns a public IP address to the group's instances. The control fails if the associated launch configuration assigns a public IP address. Amazon EC2 instances in an Auto Scaling group launch configuration should not have an associated public IP address, except for in limited edge cases. Amazon EC2 instances should only be accessible from behind a load balancer instead of being directly exposed to the internet.",
            "remediation" : "An Auto Scaling group is associated with one launch configuration at a time. You cannot modify a launch configuration after you create it. To change the launch configuration for an Auto Scaling group, use an existing launch configuration as the basis for a new launch configuration. Then, update the Auto Scaling group to use the new launch configuration. For step-by-step instructions, see Change the launch configuration for an Auto Scaling group in the Amazon EC2 Auto Scaling User Guide. When creating the new launch configuration, under Additional configuration, for Advanced details, IP address type, choose Do not assign a public IP address to any instances. After you change the launch configuration, Auto Scaling launches new instances with the new configuration options. Existing instances aren't affected. To update an existing instance, we recommend that you refresh your instance, or allow automatic scaling to gradually replace older instances with newer instances based on your termination policies. For more information about updating Auto Scaling instances, see Update Auto Scaling instances in the Amazon EC2 Auto Scaling User Guide.\nMore Information\nhttps://docs.aws.amazon.com/autoscaling/ec2/userguide/change-launch-config.html\nhttps://docs.aws.amazon.com/autoscaling/ec2/userguide/update-auto-scaling-group.html#update-auto-scaling-instances",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, launch_configurations in self.launch_configurations.items():
            for configuration in launch_configurations:
                if configuration["AssociatePublicIpAddress"] == True:
                    results["affected"].append(configuration["LaunchConfigurationName"])

        if results["affected"]:
            results["analysis"] = "The affected launch configurations are have a public ip address associated"
            results["pass_fail"] = "FAIL"
        elif self.launch_configurations:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Auto Scaling Groups In Use"
            results["affected"].append(self.account_id)

        return results

    def autoscaling_5(self):
        # Auto Scaling groups should use multiple instance types in multiple Availability Zones

        results = {
            "id" : "autoscaling_5",
            "ref" : "AutoScaling.6",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "autoscaling",
            "name" : "Auto Scaling groups should use multiple instance types in multiple Availability Zones",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon EC2 Auto Scaling group uses multiple instance types. The control fails if the Auto Scaling group has only one instance type defined. You can enhance availability by deploying your application across multiple instance types running in multiple Availability Zones. Security Hub recommends using multiple instance types so that the Auto Scaling group can launch another instance type if there is insufficient instance capacity in your chosen Availability Zones.",
            "remediation" : "To create an Auto Scaling group with multiple instance types, see Auto Scaling groups with multiple instance types and purchase options in the Amazon EC2 Auto Scaling User Guide.\nMore Information\nhttps://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, auto_scaling_groups in self.auto_scaling_groups.items():
            for group in auto_scaling_groups:
                try:
                    policy = group["MixedInstancesPolicy"]
                except KeyError:
                    results["affected"].append(group["AutoScalingGroupName"])

        if results["affected"]:
            results["analysis"] = "The affected auto scaling groups do not use multiple instance types"
            results["pass_fail"] = "FAIL"
        elif self.launch_configurations:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Auto Scaling Groups In Use"
            results["affected"].append(self.account_id)

        return results

    def autoscaling_6(self):
        # Amazon EC2 Auto Scaling groups should use Amazon EC2 launch templates

        results = {
            "id" : "autoscaling_6",
            "ref" : "AutoScaling.9",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "autoscaling",
            "name" : "Amazon EC2 Auto Scaling groups should use Amazon EC2 launch templates",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon EC2 Auto Scaling group is created from an EC2 launch template. This control fails if an Amazon EC2 Auto Scaling group is not created with a launch template or if a launch template is not specified in a mixed instances policy. An EC2 Auto Scaling group can be created from either an EC2 launch template or a launch configuration. However, using a launch template to create an Auto Scaling group ensures that you have access to the latest features and improvements.",
            "remediation" : "To create an Auto Scaling group with an EC2 launch template, see Create an Auto Scaling group using a launch template in the Amazon EC2 Auto Scaling User Guide. For information about how to replace a launch configuration with a launch template, see Replace a launch configuration with a launch template in the Amazon EC2 User Guide.\nMore Information:\nhttps://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-launch-template.html\nhttps://docs.aws.amazon.com/autoscaling/ec2/userguide/replace-launch-config.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, auto_scaling_groups in self.auto_scaling_groups.items():
            for group in auto_scaling_groups:
                try:
                    launch_template = group["LaunchTemplate"]
                except KeyError:
                    results["affected"].append(group["AutoScalingGroupName"])

        if results["affected"]:
            results["analysis"] = "The affected auto scaling groups do not use a launch template"
            results["pass_fail"] = "FAIL"
        elif self.launch_configurations:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Auto Scaling Groups In Use"
            results["affected"].append(self.account_id)

        return results

    def autoscaling_7(self):
        # EC2 Auto Scaling groups should be tagged

        results = {
            "id" : "autoscaling_7",
            "ref" : "AutoScaling.10",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "autoscaling",
            "name" : "EC2 Auto Scaling groups should be tagged",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon EC2 Auto Scaling group has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the Auto Scaling group doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the Auto Scaling group isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag. For more information, see What is ABAC for AWS? in the IAM User Guide.",
            "remediation" : "To add tags to an Auto Scaling group, see Tag Auto Scaling groups and instances in the Amazon EC2 Auto Scaling User Guide.\nMore Information\nhttps://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-tagging.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, auto_scaling_groups in self.auto_scaling_groups.items():
            for group in auto_scaling_groups:
                if not group["Tags"]:
                    results["affected"].append(group["AutoScalingGroupName"])

        if results["affected"]:
            results["analysis"] = "The affected auto scaling groups do not have any tags attached"
            results["pass_fail"] = "FAIL"
        elif self.launch_configurations:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Auto Scaling Groups In Use"
            results["affected"].append(self.account_id)

        return results
