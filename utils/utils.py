import boto3
import time

def credential_report():

    client = boto3.client('iam')

    print("Generating Credential Report")
    #client.generate_credential_report()

    while True:
        if client.generate_credential_report()["State"] == "COMPLETE":
            return client.get_credential_report()
            break
        time.sleep(3)

def password_policy():
    client = boto3.client('iam')
    return client.get_account_password_policy()["PasswordPolicy"]