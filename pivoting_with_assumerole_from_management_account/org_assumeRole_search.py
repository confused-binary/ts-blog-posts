import argparse
import json
import boto3
import sys
import re
from botocore.exceptions import ClientError


def parse_cli_args():
    """
    Process and validate command-line arguments
    """
    parser = argparse.ArgumentParser(description='This script is intended to search for in-use policies in Identity Center and report any with broadly defined AssumeRole for the Management Account.')
    parser.add_argument('--profile', default='default', help="Specify profile in credentials file to use. Defaults to 'default'.")
    arrrrrgs = parser.parse_args()
    return arrrrrgs


def boto_session_setup():
    """
    1. Create session for boto to work off of
    2. Validate access
    """
    SESSION = boto3.session.Session(profile_name=ARGS.profile)
    try:
        sts_session = SESSION.client('sts')
        ACCOUNT_ID = sts_session.get_caller_identity().get("Account")
    except ClientError as error:
        print(error)
        sys.exit()
    return SESSION


def get_instances():
    """ Get and return list of sso instances """
    instances = []
    next_token = ''
    while next_token != False:
        try:
            req = {'NextToken': next_token} if next_token else {}
            resp = SSO_CLIENT.list_instances(**req)
            next_token = resp.get('NextToken') if 'NextToken' in resp else False
            instances = instances + resp.get('Instances', [])
        except ClientError as error:
            print(error)
    return instances


def get_mgmt_acct_id():
    """ Just return mgmt acct id """
    try:
        resp = ORG_CLIENT.list_accounts()
        mgmt_acct = list(dict.fromkeys([a.get('Arn').split('/')[0] for a in resp.get('Accounts')]))[0]
        return mgmt_acct.split(':')[4]
    except ClientError as error:
        print(error)


def get_mgmt_permissions_sets(instances, mgmt_acct):
    """ Get and return list of permission sets arns """
    instances_data = {}
    next_token = ''
    for instance in [i.get('InstanceArn') for i in instances]:
        permissions_sets = []
        while next_token != False:
            try:
                req = {'InstanceArn': instance, 'AccountId': mgmt_acct}
                resp = SSO_CLIENT.list_permission_sets_provisioned_to_account(**req)
                next_token = resp.get('NextToken') if 'NextToken' in resp else False
                permissions_sets = permissions_sets + resp.get('PermissionSets')
            except ClientError as error:
                print(error)
        if instance not in instances_data:
            instances_data[instance] = permissions_sets
        else:
            instances_data[instance] = instances_data[instance] + permissions_sets
    return instances_data


def find_mgmt_assumerole_usage(instances_data, mgmt_acct):
    """ Check policies for assumeRole usage """
    flagged_data = {}
    
    # Check AWS Managed Policies
    flagged_data['AWS_Managed'] = check_aws_managed_policies(instances_data)

    # Check Customer Managed Policies
    flagged_data['Customer_Managed'] = check_customer_managed_policies(instances_data, mgmt_acct)

    # Check Inline Policies
    flagged_data['Inline'] = check_inline_policies(instances_data)

    # Check Permissions Boundaries
    flagged_policies = check_permissions_boundaries(flagged_data, mgmt_acct)

    return flagged_policies


def check_aws_managed_policies(instances_data):
    """ Check AWS Managed policies and return those with AssumeRole """
    flagged_permissions_sets = []
    for instance, permissions_set_arns in instances_data.items():
        for permission_set in permissions_set_arns:
            next_token = ''
            policies = []
            while next_token != False:
                try:
                    req = {'InstanceArn': instance, 'PermissionSetArn': permission_set}
                    if next_token:
                        req['NextToken'] = next_token
                    resp = SSO_CLIENT.list_managed_policies_in_permission_set(**req)
                    next_token = resp.get('NextToken') if 'NextToken' in resp else False
                    policies = policies + resp.get('AttachedManagedPolicies')
                except ClientError as error:
                    print(error)
            flagged_policies = check_policies(policies)
            if flagged_policies:
                flagged_permissions_sets.append({'InstanceArn': instance, 'PermissionSetArn': permission_set, 'PolicyData': flagged_policies})
    return flagged_permissions_sets


def check_customer_managed_policies(instances_data, mgmt_acct):
    """ Check Customer managed policies and return those with AssumeRole """
    flagged_permissions_sets = []
    for instance, permissions_set_arns in instances_data.items():
        for permission_set in permissions_set_arns:
            next_token = ''
            policies = []
            while next_token != False:
                try:
                    req = {'InstanceArn': instance, 'PermissionSetArn': permission_set}
                    if next_token:
                        req['NextToken'] = next_token
                    resp = SSO_CLIENT.list_customer_managed_policy_references_in_permission_set(**req)
                    next_token = resp.get('NextToken') if 'NextToken' in resp else False
                    policies = policies + resp.get('CustomerManagedPolicyReferences')
                except ClientError as error:
                    print(error)
            for policy in policies:
                policy['Arn'] = f"arn:aws:iam::{mgmt_acct}:policy/{policy.get('Name')}"
            flagged_policies = check_policies(policies)
            if flagged_policies:
                flagged_permissions_sets.append({'InstanceArn': instance, 'PermissionSetArn': permission_set, 'PolicyData': flagged_policies})
    return flagged_permissions_sets


def check_inline_policies(instances_data):
    """ Check Inline policies and return those with AssumeRole """
    flagged_permissions_sets = []
    for instance, permissions_set_arns in instances_data.items():
        for permission_set in permissions_set_arns:
            try:
                req = {'InstanceArn': instance, 'PermissionSetArn': permission_set}
                resp = SSO_CLIENT.get_inline_policy_for_permission_set(**req)
                policy = resp.get('InlinePolicy')
            except ClientError as error:
                print(error)
            if policy:
                flagged_policy = check_policy_document(json.loads(policy))
                if flagged_policy:
                    flagged_policy = [{'Name': '', 'PolicyData':  flagged_policy}]
                    flagged_permissions_sets.append({'InstanceArn': instance, 'PermissionSetArn': permission_set, 'PolicyData': flagged_policy})
    return flagged_permissions_sets


def check_permissions_boundaries(flagged_data, mgmt_acct):
    """ Compare against Permissions Boundary for each """
    tracker = {'AWS_Managed': [], 'Customer_Managed': [], 'Inline': []}
    for type, data in flagged_data.items():
        for item in data:
            flagged = False
            try:
                req = {'InstanceArn': item.get('InstanceArn'), 'PermissionSetArn': item.get('PermissionSetArn')}
                resp = SSO_CLIENT.get_permissions_boundary_for_permission_set(**req)
                boundary = resp.get('PermissionsBoundary')
                policy_name = boundary.get('CustomerManagedPolicyReference').get('Name')
                policy_arn = f"arn:aws:iam::{mgmt_acct}:policy/{policy_name}"
                policy = [{'Arn': policy_arn}]
                flagged_boundary_policy = check_policies(policy)
                if flagged_boundary_policy:
                    # remove from list since boundary doesn't allow action/resource
                    flagged = True
            except SSO_CLIENT.exceptions.ResourceNotFoundException:
                # Returns error if a Permissions Boundary does not exist on the Permissions Set
                flagged = True
            except ClientError as error:
                print(error)
            if flagged:
                tracker[type].append(item)
    return tracker


def check_policies(policies):
    """ turtles all the way down """
    flagged_policy = []
    for policy in policies:
        try:
            resp = IAM_CLIENT.get_policy(PolicyArn=policy.get('Arn',''))
            policy_version = resp.get('Policy','').get('DefaultVersionId','')
            if 'Name' not in policy:
                policy['Name'] = resp.get('Policy').get('PolicyName','')
            resp = IAM_CLIENT.get_policy_version(PolicyArn=policy.get('Arn',''), VersionId=policy_version)
            policy_document = resp.get('PolicyVersion','').get('Document','')
            flagged_policy_data = check_policy_document(policy_document)
            if flagged_policy_data:
                flagged_policy.append({'Name': policy.get('Name'), 'PolicyData': flagged_policy_data})
        except ClientError as error:
            print(error)
    return flagged_policy


def check_policy_document(policy_document):
    """ Check policy return True if broad AssumeRole is found """
    action_name = 'AssumeRole'
    regex_string = '^\*$|^sts:\*'
    name_filler = '|'.join([f'^sts:{action_name[0:n]}\*$' for n in range(1,len(action_name))])
    regex_string = f"{regex_string}|{name_filler}|^sts:{action_name}$"
    action_regex = re.compile(regex_string)

    role_name = 'AWSControlTowerExecution'
    name_filler = '|'.join(['.*'+role_name[0:n]+'\*$' for n in range(1,len(role_name))])
    regex_string = '^\*$|^arn:aws:iam::\*:\*$|^arn:aws:iam::\*:role\/\*$|^arn:aws:iam::\d{12}:\*|^arn:aws:iam::\d{12}:role\/\*'
    regex_string = f"{regex_string}|{name_filler}|.*{role_name}$"
    rescource_regex = re.compile(regex_string)
    
    flagged_policy_data = []
    for statement in policy_document.get('Statement',''):
        action_match = []
        resc_match = []
        if statement.get('Effect') != 'Allow':
            continue
        if isinstance(statement.get('Action'), str):
            res = action_regex.match(statement.get('Action'))
            if res:
                action_match.append(res.group())
        elif isinstance(statement.get('Action'), list):
            for action in statement.get('Action'):
                res = action_regex.match(action)
                if res:
                    action_match.append(res.group())
        if not action_match:
            continue
        if isinstance(statement.get('Resource'), str):
            res = rescource_regex.match(statement.get('Resource'))
            if res:
                resc_match.append(res.group())
        elif isinstance(statement.get('Resource'), list):
            for rescource in statement.get('Resource'):
                res = rescource_regex.match(rescource)
                if res:
                    resc_match.append(res.group())
    
        if action_match and resc_match:
            flagged_policy_data.append({'Actions': action_match, 'Resources': resc_match})

    # print(policy_document)
    return flagged_policy_data


def print_stuff(flagged_data):
    """ Output the data in CSV format """
    print("policyType,permissionsSetName,permissionsSetARN,policyName,actions,resources")
    for type, data in flagged_data.items():
        for item in data:
            try:
                req = {'InstanceArn': item.get('InstanceArn'), 'PermissionSetArn': item.get('PermissionSetArn')}
                resp = SSO_CLIENT.describe_permission_set(**req)
                details = resp.get('PermissionSet')
                name = details.get('Name')
                for policy in item.get('PolicyData'):
                    for specifics in policy.get('PolicyData'):
                        print(f"{type},{name},{item.get('PermissionSetArn')},{policy.get('Name')},{specifics.get('Actions')},{specifics.get('Resources')}")
            except ClientError as error:
                print(error)


def do_the_stuff():
    """
    Do all the things! \o/
    """
    
    # Get Identity Center Instance
    instances = get_instances()

    # Get Managment Account ID
    mgmt_acct = get_mgmt_acct_id()
    
    # Process list of permissions sets
    mgmt_instances_data = get_mgmt_permissions_sets(instances, mgmt_acct)
    
    # Find permissions sets with sts:AssumeRole broadly defined
    flagged_policies = find_mgmt_assumerole_usage(mgmt_instances_data, mgmt_acct)

    # Print Results
    print_stuff(flagged_policies)


###############
# Main Function
###############

if __name__ == '__main__':
    """
    This script is intended to search for in-use policies in Identity Center and 
    report any with broadly defined AssumeRole for the Management Account

    This script should be run from the Management account.
    Required Permissions:
        - organizations: ListAccounts
        - sso-admin: ListPermissionSetsProvisionedToAccount, ListInstances, ListManagedPoliciesInPermissionSet, ListCustomerManagedPolicyReferencesInPermissionSet, GetInlinePolicyForPermissionSet, GetPermissionsBoundaryForPermissionSet, DescribePermissionSet
        - iam: GetPolicyVersion, GetPolicy
    """

    # Process CLI Arguments
    ARGS = parse_cli_args()

    # Setup and validate session to work from
    SESSION = boto_session_setup()
    ORG_CLIENT = SESSION.client('organizations')
    SSO_CLIENT = SESSION.client('sso-admin')
    IAM_CLIENT = SESSION.client('iam')

    # Do the stuff
    do_the_stuff()

