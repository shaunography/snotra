import boto3
import logging
import re

from utils.utils import describe_regions
from utils.utils import get_account_id

class elb(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.classic_load_balancers = self.get_classic_load_balancers()
        self.load_balancers = self.get_load_balancers()
        self.listeners = self.get_listerners()
        self.rules = self.get_rules()
        self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.elb_1() ]
        findings += [ self.elb_2() ]
        findings += [ self.elb_3() ]
        findings += [ self.elb_4() ]
        findings += [ self.elb_5() ]
        findings += [ self.elb_6() ]
        findings += [ self.elb_7() ]
        return findings

    def get_classic_load_balancers(self):
        load_balancers = {}
        logging.info("getting classic load balancers")
        for region in self.regions:
            client = self.session.client('elb', region_name=region)
            try:
                load_balancers[region] = client.describe_load_balancers()["LoadBalancerDescriptions"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting classic load balancers - %s" % e.response["Error"]["Code"])
        return load_balancers
    
    def get_load_balancers(self):
        load_balancers = {}
        logging.info("getting load balancers")
        for region in self.regions:
            client = self.session.client('elbv2', region_name=region)
            try:
                load_balancers[region] = client.describe_load_balancers()["LoadBalancers"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting load balancers - %s" % e.response["Error"]["Code"])
        return load_balancers
    
    def get_listerners(self):
        listeners = {}
        logging.info("getting listeners")
        for region, load_balancers in self.load_balancers.items():
            client = self.session.client('elbv2', region_name=region)
            for load_balancer in load_balancers:
                arn = load_balancer["LoadBalancerArn"]
                try:
                    listeners[arn] = client.describe_listeners(LoadBalancerArn=arn)["Listeners"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting listeners - %s" % e.response["Error"]["Code"])
        return listeners
    
    def get_rules(self):
        rules = {}
        logging.info("getting rules")
        for region, load_balancers in self.load_balancers.items():
            client = self.session.client('elbv2', region_name=region)
            for load_balancer in load_balancers:
                for listener in self.listeners[load_balancer["LoadBalancerArn"]]:
                    arn = listener["ListenerArn"]
                    try:
                        rules[arn] = client.describe_rules(ListenerArn=arn)["Rules"]
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting rules - %s" % e.response["Error"]["Code"])
        return rules
    
    def elb_1(self):
        # internet facing load balancers

        results = {
            "id" : "elb_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "elb",
            "name" : "Internet Facing Load Balancers",
            "affected": [],
            "analysis" : "",
            "description" : "internet facing Elastic Load Balancers expose additional attack surface to potentiall malicious actors.",
            "remediation" : "Apply Security Groups to your load balancers using the principle of least privilege by only allowing access to services from a white list of trusted IP addresses.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        dns_names = []

        for region, load_balancers in self.classic_load_balancers.items():
            for load_balancer in load_balancers:
                if load_balancer["Scheme"] == "internet-facing":
                    results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))
                    dns_names.append("{}({}) - {}".format(load_balancer["LoadBalancerName"], region, load_balancer["DNSName"])) 

        for region, load_balancers in self.load_balancers.items():
            for load_balancer in load_balancers:
                if load_balancer["Scheme"] == "internet-facing":
                    results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))
                    dns_names.append("{}({}) - {}".format(load_balancer["LoadBalancerName"], region, load_balancer["DNSName"]))

        if results["affected"]:
            results["analysis"] = dns_names
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No internet facing load balancers found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def elb_2(self):
        # Internet facing load balancers using unencrypted http listeners

        results = {
            "id" : "elb_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "elb",
            "name" : "Internet Facing Load Balancers Using Unencrypted HTTP Listeners",
            "affected": [],
            "analysis" : "",
            "description" : 'The account under review contains Elastic Load Balancers (ELBs) that accept connection over unencrypted HTTP listeners To protect the Privacy and Integrity of data in transit between end users and your AWS hosted services it is recommended to use encrypted HTTPS listeners.',
            "remediation" : 'Disable existing HTTP listeners and replace them with HTTPS listeners as required. You can also configure HTTP listeners to redirect to HTTPS if preferred.\nMore information,nhttps://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        dns_names = []
        
        for region, load_balancers in self.classic_load_balancers.items():
            for load_balancer in load_balancers:
                if load_balancer["Scheme"] == "internet-facing":
                    for listener in load_balancer["ListenerDescriptions"]:
                        if listener["Listener"]["Protocol"] == "HTTP":
                            if "{}({})".format(load_balancer["LoadBalancerName"], region) not in results["affected"]:
                                results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))
                            dns_names.append("{}({}) - {}:{}".format(load_balancer["LoadBalancerName"], region, load_balancer["DNSName"], listener["Listener"]["LoadBalancerPort"]))

        for region, load_balancers in self.load_balancers.items():
            for load_balancer in load_balancers:
                if load_balancer["Scheme"] == "internet-facing":
                    for listener in self.listeners[load_balancer["LoadBalancerArn"]]:
                        if listener["Protocol"] == "HTTP":
                            for action in listener["DefaultActions"]: # Actions List, can there be more than one action?
                                if action["Type"] != "redirect":
                                    if "{}({})".format(load_balancer["LoadBalancerName"], region) not in results["affected"]:
                                        results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))
                                    dns_names.append("{}({}) - {}:{}".format(load_balancer["LoadBalancerName"], region, load_balancer["DNSName"], listener["Port"]))
                                else:
                                    if action["RedirectConfig"]["Protocol"] != "HTTPS":
                                        if "{}({})".format(load_balancer["LoadBalancerName"], region) not in results["affected"]:
                                            results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))
                                        dns_names.append("{}({}) - {}:{}".format(load_balancer["LoadBalancerName"], region, load_balancer["DNSName"], listener["Port"]))

        if results["affected"]:
            results["analysis"] = dns_names
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No HTTP listeners found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


    def elb_3(self):
        # ELB Listeners With Weak TLS Configuration

        results = {
            "id" : "elb_3",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "elb",
            "name" : "ELB Listeners with Weak TLS Configuration",
            "affected": [],
            "analysis" : "",
            "description" : 'The affected ALBs have an SSL/TLS protected listeners which are insufficiently protected against known cryptographic attacks which could allow a Man in the Middle (MitM) attacker to recover plain text from an encrypted SSL/TLS connection.\nTo exploit this vulnerability, an attacker must be suitably positioned to intercept and modify the victims network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defences such as switched networks are not sufficient to prevent this. An attacker situated in the users ISP or the applications hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internets core infrastructure.\nData submitted over an unencrypted connection is vulnerable to interception and can be tampered with. This could result in users sessions being compromised, credentials being captured, and sensitive and/or personal information being exposed.',
            "remediation" : 'In short, the following summarises SSL/TLS hardening options that should be considered:\n- Use 2048-bit RSA private keys and 256bit ECDSA private keys\n- Renew certificates on an annual basis\n- Use strong certificate signature algorithms (sha256)\n- Disable SSL v2, SSL v3,TLS v1.0 and TLS v1.1 - support TLS 1.2 and 1.3.\n- Disable insecure cipher suites (ADH, Null, Export, RC4 and 3DES)\n- Support Forward Secrecy (ECDHE)\n- Use strong key exchange algorithms (ECDHE and DHE > 2048-bit)\n- Ensure the underlying software is patched and up to date\n- Encrypt everything and eliminate mixed HTTP/HTTPS content\n- Implement HTTP Strict Transport Security (HSTS) to ensure secure connections cannot be downgraded to an insecure connection.\n- Support TLS_FALLBACK_SCSV to prevent protocol downgrade attacks\n- Disable SSL/TLS Compression.\nNote: Implementing a strong SSL/TLS configuration can result in user agents no longer being able to connect to your site due to lack of compatible cipher suites.',
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score" : "7.4",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        weak_cipher_regex = ".*RC4.*|.*DES.*|.*CBC3.*|.*NULL.*"
        
        for region, load_balancers in self.classic_load_balancers.items():
            client = self.session.client('elb', region_name=region)
    
            for load_balancer in load_balancers:
                if load_balancer["Scheme"] == "internet-facing":
                    try:
                        descriptions = client.describe_load_balancer_policies(LoadBalancerName=load_balancer["LoadBalancerName"])["PolicyDescriptions"]
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting load balancer policies - %s" % e.response["Error"]["Code"])
                    else:
                        for description in descriptions:
                            for attribute_description in description["PolicyAttributeDescriptions"]:
                                #if attribute_description["AttributeName"] == "Reference-Security-Policy":
                                if attribute_description["AttributeName"] == "Protocol-SSLv3":
                                    if attribute_description["AttributeValue"] == "true":
                                        if "{}({})".format(load_balancer["LoadBalancerName"], region) not in results["affected"]:
                                            results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))
                                
                                if attribute_description["AttributeName"] == "Protocol-TLSv1":
                                    if attribute_description["AttributeValue"] == "true":
                                        if "{}({})".format(load_balancer["LoadBalancerName"], region) not in results["affected"]:
                                            results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))

                                if attribute_description["AttributeName"] == "Protocol-TLSv1.1":
                                    if attribute_description["AttributeValue"] == "true":
                                        if "{}({})".format(load_balancer["LoadBalancerName"], region) not in results["affected"]:
                                            results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))
                                
                                if re.match(weak_cipher_regex, attribute_description["AttributeName"]):
                                    if attribute_description["AttributeValue"] == "true":
                                        if "{}({})".format(load_balancer["LoadBalancerName"], region) not in results["affected"]:
                                            results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))

        for region, load_balancers in self.load_balancers.items():
            for load_balancer in load_balancers:
                if load_balancer["Scheme"] == "internet-facing":
                    for listener in self.listeners[load_balancer["LoadBalancerArn"]]:
                        if listener["Protocol"] == "HTTPS":
                            if listener["SslPolicy"] != "ELBSecurityPolicy-FS-1-2-Res-2020-10":
                                if "{}({})".format(load_balancer["LoadBalancerName"], region) not in results["affected"]:
                                    results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))

        if results["affected"]:
            results["analysis"] = "The affected internet facing load balancers have HTTPS Listeners that are protected with TLS that is not configured for maximum security."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No TLS issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def elb_4(self):
        # ALBs not configured to drop invalid headers

        results = {
            "id" : "elb_4",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "elb",
            "name" : "ALBs Not Configured To Drop Invalid Headers",
            "affected": [],
            "analysis" : "",
            "description" : 'The AWS account under review is using Application Load Balancers (ALBs) that do not have protection against HTTP Request Smuggling attacks enabled.\nHTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users.\nDue to the highly distributed and segmented nature of cloud-based applications HTTP request smuggling vulnerabilities have been discovered in AWS services. Although AWS CloudFront will protect against HTTP request Smuggling by default, protection in ALBs is not enabled by default and has to be configured.\nMore information\nhttps://portswigger.net/web-security/request-smuggling',
            "remediation" : 'To help protection against HTTP Request Smuggling attacks enable the "Drop Invalid Header Fields" attribute for all affected ALBs.\nNote:\nIf your application is using nonstandard headers this may break your applications, It seems AWS considers standard headers to only include alphanumeric characters and hyphens, but it is hard to find exactly what AWS considers to be a standard header as documentation is lacking.',
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, load_balancers in self.load_balancers.items():
            client = self.session.client('elbv2', region_name=region)
            for load_balancer in load_balancers:
                if load_balancer["Scheme"] == "internet-facing":
                    try:
                        attributes = client.describe_load_balancer_attributes(LoadBalancerArn=load_balancer["LoadBalancerArn"])["Attributes"]
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting load balancer attributes - %s" % e.response["Error"]["Code"])
                    else:
                        for attribute in attributes:
                            if attribute["Key"] == "routing.http.drop_invalid_header_fields.enabled":
                                if attribute["Value"] == "false":
                                    results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))

        if results["affected"]:
            results["analysis"] = "The affected internet facing load balancers are not configured to drop invalid HTTP headers."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Application Load Balancers are configured to drop invalid HTTP headers."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def elb_5(self):
        # desync mitigation mode not enabled

        results = {
            "id" : "elb_5",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "elb",
            "name" : "ALB HTTP Desync Mitigation Mode Not Enabled",
            "affected": [],
            "analysis" : "",
            "description" : 'The account under review contains classic load balancers that do not have Desync Mitigation mode enabled. To help protect against HTTP Desync attacks it is recommended to enable Desync Mitigation mode and set it to “strictest”.\nDesync mitigation mode protects your application from issues due to HTTP Desync. The load balancer classifies each request based on its threat level, allows safe requests, and then mitigates risk as specified by the mitigation mode that you specify. The desync mitigation modes are monitor, defensive, and strictest. The default is the defensive mode, which provides durable mitigation against HTTP desync while maintaining the availability of your application. You can switch to strictest mode to ensure that your application receives only requests that comply with RFC 7230.',
            "remediation" : 'Configured Desync Mitigation Mode to "Strictest" or "Defensive" for all affected ELBs.\nMore Information\nhttps://docs.aws.amazon.com/elasticloadbalancing/latest/classic/config-desync-mitigation-mode.html',
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, load_balancers in self.load_balancers.items():
            client = self.session.client('elbv2', region_name=region)
            for load_balancer in load_balancers:
                if load_balancer["Scheme"] == "internet-facing":
                    try:
                        attributes = client.describe_load_balancer_attributes(LoadBalancerArn=load_balancer["LoadBalancerArn"])["Attributes"]
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting load balancer attributes - %s" % e.response["Error"]["Code"])
                    else:
                        for attribute in attributes:
                            if attribute["Key"] == "routing.http.desync_mitigation_mode":
                                if attribute["Value"] == "monitor":
                                    results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))

        if results["affected"]:
            results["analysis"] = "The affected internet facing load balancers do not have HTTP desync mitigation mode enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Application Load Balancers have HTTP desync mitigation mode enabled."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def elb_6(self):
        # Lack of ELB Access Logging

        results = {
            "id" : "elb_6",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "elb",
            "name" : "Lack of ELB Access Logging",
            "affected": [],
            "analysis" : "",
            "description" : 'A number of Elastic Load Balancers were identified which do not have access logging enabled.\nElastic Load Balancing provides access logs that capture detailed information about requests sent to your load balancer. Each log contains information such as the time the request was received, the clients IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and troubleshoot issues.\nIt is recommended that access logging is enabled on all public load balancers.',
            "remediation" : 'Enable ELB access logs for all affected load balancers.\nThere is no additional cost to enable the creation of ELB access logs, however there is an additional S3 cost to store the logs.\nMore Information\nhttps://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html',
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        # ELBV2
        for region, load_balancers in self.load_balancers.items():
            client = self.session.client('elbv2', region_name=region)
            for load_balancer in load_balancers:
                
                try:
                    attributes = client.describe_load_balancer_attributes(LoadBalancerArn=load_balancer["LoadBalancerArn"])["Attributes"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting load balancer attributes - %s" % e.response["Error"]["Code"])
                else:
                    for attribute in attributes:
                        if attribute["Key"] == "access_logs.s3.enabled":
                            if attribute["Value"] == "false":
                                results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))

        # ELB
        for region, load_balancers in self.classic_load_balancers.items():
            client = self.session.client('elb', region_name=region)
            for load_balancer in load_balancers:

                try:
                    attributes = client.describe_load_balancer_attributes(LoadBalancerName=load_balancer["LoadBalancerName"])["LoadBalancerAttributes"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting load balancer attributes - %s" % e.response["Error"]["Code"])
                else:
                    if attributes["AccessLog"]["Enabled"] == False:
                        results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))

        if results["affected"]:
            results["analysis"] = "The affected internet facing load balancers do not have Access Logging enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Application Load Balancers have Access Logging enabled."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


    def elb_7(self):
        # Load Balancer Deletion Protection not Configured

        results = {
            "id" : "elb_7",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "elb",
            "name" : "Load Balancer Deletion Protection not Configured",
            "affected": [],
            "analysis" : "",
            "description" : 'The AWS account under review has Elastic Load Balancers (ELB) in use that do not have deletion protection enabled. For an extra layer of protection against human error by preventing your load balancers from being deleted accidentally, you can enable deletion protection. By default, deletion protection is disabled.',
            "remediation" : 'To enable deletion protection using the console\n1.	Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/. \n2.	On the navigation pane, under LOAD BALANCING, choose Load Balancers. \n3.	Select the load balancer.\n4.	On the Description tab, choose Edit attributes. \n5.	On the Edit load balancer attributes page, select Enable for Delete Protection, and then choose Save. \n6.	Choose Save. \nTo disable deletion protection using the console\n1.	Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/. \n2.	On the navigation pane, under LOAD BALANCING, choose Load Balancers. \n3.	Select the load balancer.\n4.	On the Description tab, choose Edit attributes. \n5.	On the Edit load balancer attributes page, clear Enable for Delete Protection, and then choose Save. \n6.	Choose Save. \nNOTE: If you enable deletion protection for your load balancer, you must disable it before you can delete the load balancer.\nMore Information\nhttps://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection',
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        # ELBV2
        for region, load_balancers in self.load_balancers.items():
            client = self.session.client('elbv2', region_name=region)
            for load_balancer in load_balancers:
                
                try:
                    attributes = client.describe_load_balancer_attributes(LoadBalancerArn=load_balancer["LoadBalancerArn"])["Attributes"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting load balancer attributes - %s" % e.response["Error"]["Code"])
                else:
                    for attribute in attributes:
                        if attribute["Key"] == "deletion_protection.enabled":
                            if attribute["Value"] == "false":
                                results["affected"].append("{}({})".format(load_balancer["LoadBalancerName"], region))           

        if results["affected"]:
            results["analysis"] = "The affected internet facing load balancers do not have Deletion Protection enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Application Load Balancers have Deletion Protection enabled."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
