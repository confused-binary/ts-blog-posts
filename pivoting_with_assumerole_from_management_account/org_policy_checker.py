import argparse
import json
import boto3
import sys
from botocore.exceptions import ClientError


def parse_cli_args():
    """
    Process and validate command-line arguments
    """
    parser = argparse.ArgumentParser(description='Lambda Version Scanner.')
    
    parser.add_argument('--profile', default='default', help="Specify profile in credentials file to use. Defaults to 'default'.")
    parser.add_argument('--filter', default=['ALL'], nargs='+', help="Specify the policy type to check (SERVICE_CONTROL_POLICY, AISERVICES_OPT_OUT_POLICY, BACKUP_POLICY, TAG_POLICY). Defaults to 'ALL'")
    parser.add_argument('--mode', default='save', help="Specify 'save' to backup policy assignments to json. Specify 'restore' to restore policy assignment from json. Defaults to 'save'")
    parser.add_argument('--print-only', action='store_true', default=False, help="Just print output to screen. Doesn't save to file. Defaults to 'False'")
    parser.add_argument('--file', default='aws_orgs_policy_assignments.json', help="json file to save to or restore from. Default: aws_orgs_policy_assignments.json")
    parser.add_argument('--verbose', action='store_true', default=False, help=f"Report output every step of the way. Defaults to 'False'")
    
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
        if ARGS.verbose:
            print(f"Validated BOTO3 Session for Account #{ACCOUNT_ID}")
    except ClientError as error:
        print(error)
        sys.exit()
    return SESSION


def get_data(orgs_client):
    """
    Get policy data from AWS
    """
    data = {}
    for filter in ARGS.filter:
        try:
            resp = orgs_client.list_policies(Filter=filter)
            policies = resp.get('Policies')
        except ClientError as error:
            print(error)
        try:
            for policy in policies:
                resp = orgs_client.list_targets_for_policy(PolicyId=policy.get('Id'))
                policy['Targets'] = resp.get('Targets')
        except ClientError as error:
            print(error)
        data[filter] = policies

    return data


def just_print(orgs_client):
    """
    Just print current settings to screen and exit
    """
    data = get_data(orgs_client)
    print('filter_policy, policy_name, policy_id, policy_targets')
    for key, value in data.items():
        for entry in value:
            target_list = '; '.join([a.get('TargetId') for a in entry.get('Targets') if a.get('Type') == 'ACCOUNT'])
            if not target_list:
                target_list = 'No Attachments'
            print(f"{key}, {entry.get('Name')}, {entry.get('Id')}, {target_list}")


def save_policy_attachments(orgs_client):
    """
    Save policies to json for safe keeping
    """
    data = get_data(orgs_client)
    with open(ARGS.file, "w") as outfile:
        outfile.write(json.dumps(data, indent=4))
    just_print(orgs_client)
    print(f"Saved to {ARGS.file}")


def restore_policy_attachments(orgs_client):
    """
    Restore policy assignment to accounts based on json file
    Only restores attachments to acounts atm
    """
    json_file = open(ARGS.file)
    data = json.load(json_file)
    for filter, policies in data.items():
        for policy in policies:
            if not policy.get('Targets'):
                continue
            for target in policy.get('Targets'):
                if target.get('Type') != 'ACCOUNT':
                    continue
                try:
                    resp = orgs_client.list_policies_for_target(Filter=filter, TargetId=target.get('TargetId'))
                    if policy.get('Id') in [a.get('Id') for a in resp.get('Policies')]:
                        continue
                    resp = orgs_client.attach_policy(PolicyId=policy.get('Id'), TargetId=target.get('TargetId'))
                except ClientError as error:
                    print(error)
                pass
            pass
        pass
    pass


def do_the_stuff():
    """
    Do the stuff
    """
    if 'ALL' in ARGS.filter:
        ARGS.filter = ['SERVICE_CONTROL_POLICY', 'AISERVICES_OPT_OUT_POLICY', 'BACKUP_POLICY', 'TAG_POLICY']
    orgs_client = SESSION.client('organizations')
    if ARGS.print_only:
        just_print(orgs_client)
        sys.exit()
    if ARGS.mode.lower() == 'save':
        save_policy_attachments(orgs_client)
    if ARGS.mode.lower() == 'restore':
        restore_policy_attachments(orgs_client)


###############
# Main Function
###############

if __name__ == '__main__':
    """
    This script can be used to backup SCP assignments and potentially restore them if needed
    """
    # Process CLI Arguments
    ARGS = parse_cli_args()

    # Setup and validate session to work from
    SESSION = boto_session_setup()

    # Do the stuff
    do_the_stuff()

