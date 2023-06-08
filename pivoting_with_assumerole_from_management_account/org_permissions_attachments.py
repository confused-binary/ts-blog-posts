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
    parser.add_argument('-p', '--profile', default='default', help="Specify profile in credentials file to use. Defaults to 'default'.")
    parser.add_argument('-u', '--users', default='ALL', help="Specify profile in credentials file to use. Defaults to 'default'.")
    parser.add_argument('-g', '--groups', default='ALL', help="Specify profile in credentials file to use. Defaults to 'default'.")
    parser.add_argument('-a', "--actions", nargs='+', default=['xlsx'], help="Specify report format (csv, xlsx, png). Defaults to xlsx")
    parser.add_argument('-r', "--resource", nargs='+', default=['xlsx'], help="Specify report format (csv, xlsx, png). Defaults to xlsx")
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
            if next_token:
                req['NextToken'] = next_token
            resp = SSO_CLIENT.list_instances(**req)
            instances = instances + resp.get('Instances', [])
            next_token = resp.get('NextToken') if 'NextToken' in resp else False
        except ClientError as error:
            print(error)
    return instances


def do_the_stuff():
    """
    Do all the things! \o/
    """
        
    # Get Instances
    instances = get_instances() 

    # Get list of users
    identity_data = get_ids_users(instances)
    
    # Get user to groups
    identity_data = get_ids_groups(identity_data)

    # Map Users to Groups and vice versa
    identity_data = map_group_membership(identity_data)

    # Get Permissions Sets for Users
    identity_data = get_permission_sets(identity_data)

    # Enrich Permission Set Data
    identity_data = get_permission_set_policies(identity_data)
    identity_data = get_permission_set_names(identity_data)
    
    # Get Permission Set Assignments for Accounts
    identity_data = get_permissions_set_assignments(identity_data)

    # Print Results
    print_data(identity_data)


def get_ids_users(instances):
    """ Get and return Users from Identity Store """
    identity_data = {}
    for instance in instances:
        identity_data[instance.get('IdentityStoreId')] = {'Users': {}, 'Groups': {}}
        next_token = ''
        while next_token != False:
            try:
                req = {'IdentityStoreId': instance.get('IdentityStoreId')}
                if next_token:
                    req['NextToken'] = next_token
                resp = IDS_CLIENT.list_users(**req)
                next_token = resp.get('NextToken') if 'NextToken' in resp else False
                for user in resp.get('Users'):
                    identity_data[instance.get('IdentityStoreId')]['Users'][user.get('UserName')] = user
            except ClientError as error:
                print(error)
    return identity_data


def get_ids_groups(identity_data):
    """ Get and return groups that users are part of """
    for identity_store, data in identity_data.items():
        next_token = ''
        while next_token != False:
            try:
                req = {'IdentityStoreId': identity_store}
                if next_token:
                    req['NextToken'] = next_token
                resp = IDS_CLIENT.list_groups(**req)
                next_token = resp.get('NextToken') if 'NextToken' in resp else False
                groups = resp.get('Groups')
                for group in groups:
                    data['Groups'][group.get('DisplayName')] = group
            except ClientError as error:
                print(error)
    return identity_data


def map_group_membership(identity_data):
    """ Add users to group objects and vice versa """
    for identity_store, data in identity_data.items():
        user_id_map = {v.get('UserId'): v.get('UserName') for v in data.get('Users').values()}
        user_id_map_rev = {v: k for k, v in user_id_map.items()}
        data['User_ID_Map'] = {**user_id_map, **user_id_map_rev}
        
        group_id_map = {v.get('GroupId'): v.get('DisplayName') for v in data.get('Groups').values()}
        group_id_map_rev = {v: k for k, v in group_id_map.items()}
        data['Group_ID_Map'] = {**group_id_map, **group_id_map_rev}

        for group in data.get('Groups').values():
            next_token = ''
            while next_token != False:
                try:
                    req = {'IdentityStoreId': identity_store, 'GroupId': group.get('GroupId')}
                    if next_token:
                        req['NextToken'] = next_token
                    resp = IDS_CLIENT.list_group_memberships(**req)
                    next_token = resp.get('NextToken') if 'NextToken' in resp else False
                    group_members = resp.get('GroupMemberships')
                    for member in group_members:
                        user_id = member.get('MemberId').get('UserId')
                        data['Users'][user_id_map[user_id]]['Groups'] = group
                        if 'Members' not in group:
                            group['Members'] = {}
                        group['Members'][user_id_map[user_id]] = data['Users'][user_id_map[user_id]]
                except ClientError as error:
                    print(error)
    return identity_data


def get_permission_sets(identity_data):
    """ Get and return list of permission sets arns - returns only those in use"""
    next_token = ''
    for data in identity_data.values():
        for instance in [i.get('InstanceArn') for i in get_instances()]:
            mgmt_acct = get_mgmt_acct_id()
            while next_token != False:
                try:
                    req = {'InstanceArn': instance, 'AccountId': mgmt_acct}
                    if next_token:
                        req['NextToken'] = next_token
                    resp = SSO_CLIENT.list_permission_sets_provisioned_to_account(**req)
                    next_token = resp.get('NextToken') if 'NextToken' in resp else False
                    if 'PermissionsSets' not in data:
                        data['PermissionSets'] = []
                    data['PermissionSets'] = data['PermissionSets'] + resp.get('PermissionSets')
                    data['AccountId'] = mgmt_acct
                    data['InstanceArn'] = instance
                except ClientError as error:
                    print(error)
    return identity_data


def get_instances():
    """ Get and return list of sso instances """
    instances = []
    next_token = ''
    while next_token != False:
        try:
            req = {'NextToken': next_token} if next_token else {}
            if next_token:
                req['NextToken'] = next_token
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


def get_permission_set_policies(identity_data):
    """ Get and Return Permission Set policy details """
    for data in identity_data.values():
        permission_set_data = {}
        for PermissionSetArn in data.get('PermissionSets'):
            InstanceArn = data.get('InstanceArn')
            AccountId = data.get('AccountId')
            permission_set_data[PermissionSetArn] = {}
            
            # Get AWS Managed Policies
            permission_set_data[PermissionSetArn]["AWS_Managed"] = get_aws_managed_policies(InstanceArn, PermissionSetArn)
            # Get Customer Managed Policies
            permission_set_data[PermissionSetArn]["Customer_Managed"] = get_customer_managed_policies(InstanceArn, PermissionSetArn, AccountId)
            # Get Inline Policy
            permission_set_data[PermissionSetArn]["Inline"] = get_inline_policy(InstanceArn, PermissionSetArn)
            # Get Permission Boundary Policy
            permission_set_data[PermissionSetArn]["Permission_Boundary"] = get_permissions_boundary(InstanceArn, PermissionSetArn, AccountId)

        data['PermissionSets'] = permission_set_data
    return identity_data


def get_aws_managed_policies(InstanceArn, PermissionSetArn):
    """ Get and return AWS Managed policies for Permission Set"""
    next_token = ''
    policies = []
    while next_token != False:
        try:
            req = {'InstanceArn': InstanceArn, 'PermissionSetArn': PermissionSetArn}
            if next_token:
                req['NextToken'] = next_token
            resp = SSO_CLIENT.list_managed_policies_in_permission_set(**req)
            next_token = resp.get('NextToken') if 'NextToken' in resp else False
            policies = policies + resp.get('AttachedManagedPolicies')
            for policy in policies:
                policy['PolicyDocument'] = get_policy(policy)
        except ClientError as error:
            print(error)
    return policies


def get_customer_managed_policies(InstanceArn, PermissionSetArn, AccountId):
    """ Get and return Customer Managed policies for Permission Set"""
    next_token = ''
    policies = []
    while next_token != False:
        try:
            req = {'InstanceArn': InstanceArn, 'PermissionSetArn': PermissionSetArn}
            if next_token:
                req['NextToken'] = next_token
            resp = SSO_CLIENT.list_customer_managed_policy_references_in_permission_set(**req)
            next_token = resp.get('NextToken') if 'NextToken' in resp else False
            policies = policies + resp.get('CustomerManagedPolicyReferences')
            for policy in policies:
                policy['Arn'] = f"arn:aws:iam::{AccountId}:policy/{policy.get('Name')}"
                policy['PolicyDocument'] = get_policy(policy)
        except ClientError as error:
            print(error)
    return policies


def get_inline_policy(InstanceArn, PermissionSetArn):
    """ Get and return Inline policy for Permission Set """
    try:
        req = {'InstanceArn': InstanceArn, 'PermissionSetArn': PermissionSetArn}
        resp = SSO_CLIENT.get_inline_policy_for_permission_set(**req)
        policy = resp.get('InlinePolicy')
    except ClientError as error:
        print(error)
    if policy:
        return json.loads(policy)
    return {}


def get_permissions_boundary(InstanceArn, PermissionSetArn, AccountId):
    """ Compare against Permissions Boundary for each """
    try:
        req = {'InstanceArn': InstanceArn, 'PermissionSetArn': PermissionSetArn}
        resp = SSO_CLIENT.get_permissions_boundary_for_permission_set(**req)
        boundary = resp.get('PermissionsBoundary')
        policy_name = boundary.get('CustomerManagedPolicyReference').get('Name')
        policy_arn = f"arn:aws:iam::{AccountId}:policy/{policy_name}"
        return get_policy({'Arn': policy_arn})
    except SSO_CLIENT.exceptions.ResourceNotFoundException:
        # Returns error if a Permissions Boundary does not exist on the Permissions Set
        pass
    except ClientError as error:
        print(error)
    return {}


def get_policy(policy):
    """ turtles all the way down """
    flagged_policy = []
    try:
        resp = IAM_CLIENT.get_policy(PolicyArn=policy.get('Arn',''))
        policy_version = resp.get('Policy','').get('DefaultVersionId','')
        if 'Name' not in policy:
            policy['Name'] = resp.get('Policy').get('PolicyName','')
        resp = IAM_CLIENT.get_policy_version(PolicyArn=policy.get('Arn',''), VersionId=policy_version)
        policy['PolicyDocument'] = resp.get('PolicyVersion','').get('Document','')
        policy_document = resp.get('PolicyVersion','').get('Document','')
    # return policies
    #         flagged_policy_data = check_policy_document(policy_document)
    #         if flagged_policy_data:
    #             flagged_policy.append({'Name': policy.get('Name'), 'PolicyData': flagged_policy_data})
    except ClientError as error:
        print(error)
    return policy_document
    # return flagged_policy


def get_policies(policies):
    """ turtles all the way down """
    for policy in policies:
        try:
            resp = IAM_CLIENT.get_policy(PolicyArn=policy.get('Arn',''))
            policy_version = resp.get('Policy','').get('DefaultVersionId','')
            if 'Name' not in policy:
                policy['Name'] = resp.get('Policy').get('PolicyName','')
            resp = IAM_CLIENT.get_policy_version(PolicyArn=policy.get('Arn',''), VersionId=policy_version)
            policy['PolicyDocument'] = resp.get('PolicyVersion','').get('Document','')
            policy_document = resp.get('PolicyVersion','').get('Document','')
        except ClientError as error:
            print(error)
    return policies


def get_permission_set_names(identity_data):
    """ Get and return Display Names for Permission Sets """
    for identity_store, data in identity_data.items():
        for permission_set, permission_data in data.get('PermissionSets').items():
                next_token = ''
                while next_token != False:
                    try:
                        req = {'InstanceArn': data.get('InstanceArn'), 'PermissionSetArn': permission_set}
                        if next_token:
                            req['NextToken'] = next_token
                        resp = SSO_CLIENT.describe_permission_set(**req)
                        next_token = resp.get('NextToken') if 'NextToken' in resp else False
                        permission_data = {**permission_data, **resp.get('PermissionSet')}
                        identity_data[identity_store]['PermissionSets'][permission_set] = permission_data
                    except ClientError as error:
                        print(error)
    return identity_data


def get_permissions_set_assignments(identity_data):
    """ Add Permissions Sets details to data object """
    for data in identity_data.values():
        for permission_set in data.get('PermissionSets'):
                next_token = ''
                while next_token != False:
                    try:
                        req = {'InstanceArn': data.get('InstanceArn'), 'AccountId': data.get('AccountId'), 'PermissionSetArn': permission_set}
                        if next_token:
                            req['NextToken'] = next_token
                        resp = SSO_CLIENT.list_account_assignments(**req)
                        next_token = resp.get('NextToken') if 'NextToken' in resp else False
                        if 'PermissionMapping' not in data:
                            data['PermissionMapping'] = []
                        data['PermissionMapping'] = data['PermissionMapping'] + resp.get('AccountAssignments')
                        # assignments = {permission_set: resp.get('AccountAssignments')}
                        # if 'PermissionMapping' not in data:
                        #     data['PermissionMapping'] = {}
                        # data['PermissionMapping'] = data['PermissionMapping'] = {**data['PermissionMapping'], **assignments}
                    except ClientError as error:
                        print(error)
    return identity_data


def print_data(identity_data):
    """ Print Results """
    print("userName,attachmentDetails,permissionsSet,account")
    for data in identity_data.values():
        user_attachments  = [a for a in data.get('PermissionMapping') if a.get('PrincipalType') == 'USER']
        for user in user_attachments:
            identity = user.get('PrincipalId')
            username = data.get('User_ID_Map').get(identity)
            permission_set_name = data.get('PermissionSets').get(user.get('PermissionSetArn')).get('Name')
            print(f"{username},direct user attachment,{permission_set_name},{user.get('AccountId')}")

        group_attachments = [a for a in data.get('PermissionMapping') if a.get('PrincipalType') == 'GROUP']
        for group in group_attachments:
            identity = group.get('PrincipalId')
            groupname = data.get('Group_ID_Map').get(identity)
            permission_set_name = data.get('PermissionSets').get(group.get('PermissionSetArn')).get('Name')
            
            group_details = data.get('Groups').get(groupname)
            if 'Members' in group_details:
                users = list(group_details.get('Members').keys())
                for user in users:
                    group_line  = f'{user},{groupname} group-attachment,{permission_set_name},{group.get("AccountId")}'
                    print(group_line)


###############
# Main Function
###############

if __name__ == '__main__':
    """
    This script is to report attached user and user-group identity
    attachments to accounts in AWS Identity Center and Organizations

    This script should be run from the Management account.
    Required Permissions:
        - sso:ListInstances, ListGroupMemberships, ListPermissionSetsProvisionedToAccount, ListManagedPoliciesInPermissionSet, ListCustomerManagedPolicyReferencesInPermissionSet, GetInlinePolicyForPermissionSet, GetPermissionsBoundaryForPermissionSet, ListManagedPoliciesInPermissionSet, DescribePermissionSet, ListAccountAssignments
        - organizations: ListAccounts
    """

    # Process CLI Arguments
    ARGS = parse_cli_args()

    # Setup and validate session to work from
    SESSION = boto_session_setup()
    ORG_CLIENT = SESSION.client('organizations')
    SSO_CLIENT = SESSION.client('sso-admin')
    IDS_CLIENT = SESSION.client('identitystore')
    IAM_CLIENT = SESSION.client('iam')

    # Do the stuff
    do_the_stuff()

