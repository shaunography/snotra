import requests
import json

import logging
import re

class graph(object):

    def __init__(self, credential, tenant):
        self.credential = credential
        self.tenant = tenant
        self.access_token = credential.get_token("https://graph.microsoft.com/.default").token
        self.skus = self.get_skus()
        self.premium = self.get_premium()
        self.users = self.get_users()
        self.guests = self.get_guests()
        self.roles = self.get_roles()
        self.global_admins = self.get_global_admins()
        self.conditional_access_policies = self.get_conditional_access_policies()
        self.applications = self.get_applications()
        self.service_principals = self.get_service_principals()

    def get_skus(self):
        url = "https://graph.microsoft.com/v1.0/subscribedSkus"
        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting users')
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting skus: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting skus: , access denied:')
            else:
                logging.error(f'error getting skus: , error: { e }')
    def get_premium(self):
        for sku in self.skus:
            if re.match("AAD_PREMIUM*", sku["skuPartNumber"]):
                logging.info("azure ad premium in use")
                return True


    def get_users(self):
        url = "https://graph.microsoft.com/v1.0/users"
        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting users')
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting users: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting conditional access policies: , access denied: Policy.Read.All required')
            else:
                logging.error(f'error getting users: , error: { e }')

    def get_guests(self):
        url = "https://graph.microsoft.com/v1.0/users/?$filter=userType eq 'Guest'"
        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting users')
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting users: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting conditional access policies: , access denied: Policy.Read.All required')
            else:
                logging.error(f'error getting users: , error: { e }')

    def get_roles(self):
        url = "https://graph.microsoft.com/v1.0/directoryRoles"
        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting roles')
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting roles: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting roles: , access denied:')
            else:
                logging.error(f'error getting roles: , error: { e }')

    def get_global_admins(self):
        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting global admins')
        for role in self.roles:
            if role["displayName"] == "Global Administrator":
                id = role["id"]
                url = f"https://graph.microsoft.com/v1.0/directoryRoles/{ id }/members"
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting roles: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting roles: , access denied:')
            else:
                logging.error(f'error getting roles: , error: { e }')


    def get_conditional_access_policies(self):
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting conditional access policies')
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting conditional access policies: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting conditional access policies: , access denied: Policy.Read.All required')
            else:
                logging.error(f'error getting conditional access policies: , error: { e }')

    def get_applications(self):
        url = "https://graph.microsoft.com/v1.0/applications"
        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting applications')
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting application: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting applications: , access denied:')
            else:
                logging.error(f'error getting applications: , error: { e }')

    def get_service_principals(self):
        url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting service principals')
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting service principals: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting service principals: , access denied:')
            else:
                logging.error(f'error getting service principals: , error: { e }')

    def run(self):
        findings = []
        findings += [ self.graph_1() ]
        findings += [ self.graph_2() ]
        findings += [ self.graph_3() ]
        findings += [ self.graph_4() ]
        findings += [ self.graph_5() ]
        findings += [ self.graph_6() ]
        findings += [ self.graph_7() ]
        #findings += [ self.graph_8() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.graph_1() ]
        return findings

    def graph_1(self):
        # Ensure Security Defaults is enabled on Microsoft Entra ID (CIS)

        results = {
            "id" : "graph_1",
            "ref" : "1.1.1",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure Security Defaults is enabled on Microsoft Entra ID (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Security defaults in Microsoft Entra ID make it easier to be secure and help protect your organization. Security defaults contain preconfigured security settings for common attacks. \nSecurity defaults is available to everyone. The goal is to ensure that all organizations have a basic level of security enabled at no extra cost. You may turn on security defaults in the Azure portal.\nSecurity defaults provide secure default settings that we manage on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings.\nFor example, doing the following:\n• Requiring all users and admins to register for MFA.\n• Challenging users with MFA - when necessary, based on factors such as location, device, role, and task.\n• Disabling authentication from legacy authentication clients, which can’t do MFA.\nThis recommendation should be implemented initially and then may be overridden by other service/product specific CIS Benchmarks. Administrators should also be aware that certain configurations in Microsoft Entra ID may impact other Microsoft services such as Microsoft 365.",
            "remediation" : "To enable security defaults in your directory:\n1. From Azure Home select the Portal Menu.\n2. Browse to Microsoft Entra ID > Properties\n3. Select Manage security defaults\n4. Set the Enable security defaults to Enabled\n5. Select Save",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if not self.premium:
            url = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy/"
            headers = {"Authorization": "Bearer " + self.access_token}

            try:
                response = requests.get(url, headers=headers)
            except Exception as e:
                logging.error(f'error getting security defaults: , error: { e }')
            else:
                if response.status_code == 200:
                    if response.json()["isEnabled"] != True:
                        results["analysis"] = "Security Defaults is disabled. (If Conditional Access is in use, this should be ignored)"
                        results["affected"] = self.tenant

            if results["affected"]:
                results["pass_fail"] = "FAIL"
            else:
                results["pass_fail"] = "PASS"

        return results

    def graph_2(self):
        # Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users (CIS)

        results = {
            "id" : "graph_2",
            "ref" : "1.1.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Enable multi-factor authentication for all roles, groups, and users that have write access or permissions to Azure resources. These include custom created objects or built-in roles such as;\n• Service Co-Administrators\n• Subscription Owners\n• Contributors\n\nMulti-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.\nUsers would require two forms of authentication before any access is granted. Additional administrative time will be required for managing dual forms of authentication when enabling multi-factor authentication.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID blade\n3. Select Users\n4. Take note of all users with the role Service Co-Administrators, Owners or\nContributors\n5. Click on the Per-User MFA button in the top row menu\n6. Check the box next to each noted user\n7. Click Enable under quick steps in the right-hand panel\n8. Click enable multi-factor auth\n9. Click close",
            "impact" : "high",
            "probability" : "high",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score" : "9.1",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if not self.premium:
            for user in self.global_admins:
                try:
                    headers = {"Authorization": "Bearer " + self.access_token}
                    url = f"https://graph.microsoft.com/v1.0/users/{ user['id'] }/authentication/methods"
                    response = requests.get(url, headers=headers)
                except Exception as e:
                    logging.error(f'error getting security defaults: , error: { e }')
                else:
                    if response.status_code == 200:
                        enabled = False
                        authentication_methods = response.json()["value"]
                        for method in authentication_methods:
                            print(method)
                            if method["@odata.type"] == "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#emailAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#fido2AuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#phoneAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#microsoft.graph.softwareOathAuthenticationMethod":
                                enabled = True
                        if not enabled:
                            results["affected"].append(user["userPrincipalName"])

                    if response.status_code == 404:
                        logging.error(f'{ user["mail"] } user not found')



            if results["affected"]:
                results["pass_fail"] = "FAIL"
            else:
                results["pass_fail"] = "PASS"

        return results
    def graph_3(self):
        # Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users (CIS)

        results = {
            "id" : "graph_3",
            "ref" : "1.1.3",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Enable multi-factor authentication for all non-privileged users.\nMulti-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.\n Users would require two forms of authentication before any access is granted. Also, this requires an overhead for managing dual forms of authentication.",
            "remediation" : "Follow Microsoft Azure documentation and enable multi-factor authentication in your environment.\nhttps://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa\nEnabling and configuring MFA is a multi-step process. Here are some additional resources on the process within Microsoft Entra ID:\nhttps://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa\nhttps://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-getstarted#enable-multi-factor-authentication-with-conditional-access\nhttps://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "6.5",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if not self.premium:
            for user in self.users:
                try:
                    headers = {"Authorization": "Bearer " + self.access_token}
                    url = f"https://graph.microsoft.com/v1.0/users/{ user['id'] }/authentication/methods"
                    response = requests.get(url, headers=headers)
                except Exception as e:
                    logging.error(f'error getting security defaults: , error: { e }')
                else:
                    if response.status_code == 200:
                        enabled = False
                        authentication_methods = response.json()["value"]
                        for method in authentication_methods:
                            if method["@odata.type"] == "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#emailAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#fido2AuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#phoneAuthenticationMethod":
                                enabled = True

                        if not enabled:
                            results["affected"].append(user["userPrincipalName"])

                    if response.status_code == 404:
                        logging.error(f'{ user["mail"] } user not found')



            if results["affected"]:
                results["pass_fail"] = "FAIL"
            else:
                results["pass_fail"] = "PASS"

        return results


    def graph_4(self):
        # Lack Of Conditional Access (CIS)

        results = {
            "id" : "greph_4",
            "ref" : "1.2.1-7",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Lack Of Conditional Access (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "The account under review did not implement a comprehensive set of conditional access policies to control user authentication and resource access. Securing the identity of users, especially administrators, is fundamental to protecting your cloud environment from unauthorised access and data compromise.\nOne of the Azure key security principles states to explicitly validate trusted signals to allow or deny user access to resources, as part of a zero-trust access model. Signals to validate should include strong authentication of user accounts, behavioural analytics of user accounts, device trustworthiness, user or group membership and trusted locations etc. Additionally enforcing a time out for MFA will help ensure that sessions are not kept alive for an indefinite period of time and ensuring that browser sessions are not persistent will help in prevention of drive-by attacks in web browsers. This configuration also prevents the creation and saving of user-based session cookies which prevents an attacker from leveraging compromised sessions to access a Tenant.",
            "remediation" : "For organisations which maintain the appropriate licenses (Azure AD Premium P1 minimum), Azure Conditional Access policies should be utilised to assist a zero-trust architecture through granular access controls and organisational policies.\nConditional access policies can be based on common signals such as, user and group membership, IP location, device type and application access and can be used to block or grant access based on several options such as compliance and MFA. Organisations should review the applications and services in use within a Tenant and configure conditional access policies that define the required criteria under which users are able to access resources. \nThe following common use cases should be considered: \nRequiring multi-factor authentication for users with administrative roles. \nRequiring multi-factor authentication for all users. \nRequiring multi-factor authentication for Azure management tasks \nBlocking sign-ins for users attempting to use legacy authentication protocols. \nRequiring trusted locations for Azure AD Multi-Factor Authentication registration \nBlocking access from geographic locations that are deemed out-of-scope for your organization or application. \nDefine Trusted Locations from which access can be limited to. \nBlocking risky sign-in behaviours. \nRequiring organization-managed devices for specific applications. \nCreate a policy that specifies Sign-in frequency set to the time determined by your organization and that Persistent browser session is set to Never persistent. \nCreate a policy to block access to the Microsoft Azure Management Cloud Apps for non-administrative users. \nFurther Information \nhttps://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions \nhttps://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-cloud-apps \nhttps://www.cisecurity.org/benchmark/azure - section 1.2",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if self.premium:
            if not self.conditional_access_policies:
                results["affected"] = self.tenant
                results["analysis"] = "No conditional access policies in use"
            else:
                for policy in self.conditional_access_policies:
                    print(policy)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        else:
            results["pass_fail"] = "PASS"

        return results


    def graph_5(self):
        # Ensure Guest Users Are Reviewed on a Regular Basis (CIS)

        results = {
            "id" : "graph_5",
            "ref" : "1.4",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure Guest Users Are Reviewed on a Regular Basis (CIS)",
            "affected": [],
            "analysis" : [],
            "description" : "Microsoft Entra ID is extended to include Azure AD B2B collaboration, allowing you to invite people from outside your organization to be guest users in your cloud account and sign in with their own work, school, or social identities. Guest users allow you to share your company's applications and services with users from any other organization, while maintaining control over your own corporate data. Work with external partners, large or small, even if they don't have Azure AD or an IT department. A simple invitation and redemption process lets partners use their own credentials to access your company's resources as a guest user. Guest users in every subscription should be review on a regular basis to ensure that inactive and unneeded accounts are removed.\nGuest users in the Microsoft Entra ID are generally required for collaboration purposes in Office 365, and may also be required for Azure functions in enterprises with multiple Azure tenants. Guest users are typically added outside your employee on-boarding/off-boarding process and could potentially be overlooked indefinitely, leading to a potential vulnerability. To prevent this, guest users should be reviewed on a regular basis. During this audit, guest users should also be determined to not have administrative privileges.\nBefore removing guest users, determine their use and scope. Like removing any user, there may be unforeseen consequences to systems if it is deleted.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Click on Add filter\n5. Select User type\n6. Select Guest from the Value dropdown\n7. Click Apply\n8. Delete all Guest users that are no longer required or are inactive",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if not self.guests:
            results["analysis"] = f"no guest users found"
        else:
            for user in self.guests:
                results["affected"] = self.tenant
                results["analysis"].append(user["userPrincipalName"])
                results["pass_fail"] = "INFO"


        return results

    def graph_6(self):
        # Ensure fewer than 5 users have global administrator assignment (CIS)

        results = {
            "id" : "graph_6",
            "ref" : "1.25",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure fewer than 5 users have global administrator assignment (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "This recommendation aims to maintain a balance between security and operational efficiency by ensuring that a minimum of 2 and a maximum of 4 users are assigned the Global Administrator role in Microsoft Entra ID. Having at least two Global Administrators ensures redundancy, while limiting the number to four reduces the risk of excessive privileged access.\nThe Global Administrator role has extensive privileges across all services in Microsoft Entra ID. The Global Administrator role should never be used in regular daily activities; administrators should have a regular user account for daily activities, and a separate account for administrative responsibilities. Limiting the number of Global Administrators helps mitigate the risk of unauthorized access, reduces the potential impact of human error, and aligns with the principle of least privilege to reduce the attack surface of an Azure tenant. Conversely, having at least two Global Administrators ensures that administrative functions can be performed without interruption in case of unavailability of a single admin.\nImplementing this recommendation may require changes in administrative workflows or the redistribution of roles and responsibilities. Adequate training and awareness should be provided to all Global Administrators.",
            "remediation" : "If more 4 users are assigned:\n1. Remove Global Administrator role for users which do not or no longer require the role.\n2. Assign Global Administrator role via PIM which can be activated when required.\n3. Assign more granular roles to users to conduct their duties.\nIf only one user is assigned:\n1. Provide the Global Administrator role to a trusted user or create a break glass admin account.",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "7.3",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if len(self.global_admins) > 4:
            results["affected"] = self.tenant
            results["analysis"] = f"there are currently { len(self.global_admins) } global admins in the tenancy"
            results["pass_fail"] = "FAIL"
        else:
            results["pass_fail"] = "PASS"
            results["analysis"] = f"there are only { len(self.global_admins) } global admins in the tenancy"

        return results

    def graph_7(self):
        # Ensure 'Self service password reset enabled' is set to 'All'

        results = {
            "id" : "graph_7",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "graph",
            "name" : "Ensure 'Self service password reset enabled' is set to 'All'",
            "affected": [],
            "analysis" : {},
            "description" : "Enabling self-service password reset allows users to reset their own passwords in Azure AD. When users sign in to Microsoft 365 or Azure, they will be prompted to enter additional contact information that will help them reset their password in the future. If combined registration is enabled additional information, outside of multi-factor, will not be needed. Users will no longer need to engage the helpdesk for password resets, and the password reset mechanism will automatically block common, easily guessable passwords.",
            "remediation" : "To enable self-service password reset:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Protection > Password reset select Properties.\n3. Set Self service password reset enabled to All",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        headers = {"Authorization": "Bearer " + self.access_token}
        logging.info(f'getting global admins')
        url = f"https://graph.microsoft.com/v1.0/policies/authenticationFlowsPolicy"
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f'error getting authentication flows: , error: { e }')
        else:
            if response.status_code == 200:

                if response.json()["selfServiceSignUp"]["isEnabled"] == False:
                    results["affected"] = self.tenant
                    results["analysis"] = "Self-Service Password Reset is not enabled"
                    results["pass_fail"] = "FAIL"
                else:
                    results["pass_fail"] = "PASS"
                    results["analysis"] = "Self-Service Password Reset is enabled"

            elif response.status_code == 403:
                logging.error(f'error getting conditional access policies: , access denied: Policy.Read.All required')
            else:
                logging.error(f'error getting users: , error: { e }')

        return results

    def graph_8(self):
        # 

        results = {
            "id" : "graph_8",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "graph",
            "name" : "",
            "affected": [],
            "analysis" : {},
            "description" : "",
            "remediation" : "",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        privileged_roles = [
                "Global Administrator",
                "Exchange Administrator",
                "User Administrator",
                ]

        for service_principal in self.service_principals:
            #print(service_principal)
            url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{ service_principal['id'] }/memberOf"
            headers = {"Authorization": "Bearer " + self.access_token}
            response = requests.get(url, headers=headers)
            for role in response.json()["value"]:
                if role['displayName'] == 'Global Administrator':
                    print(service_principal)

        #for role in self.roles:
            #print(role)

        #for member in self.global_admins:
            #print(member)


        return results
