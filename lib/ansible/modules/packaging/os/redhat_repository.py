#!/usr/bin/python

# Giovanni Sciortino (giovannibattistasciortino@gmail.com)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: redhat_repository
short_description: Manage RHSM repositories using the C(subscription-manager) command
description:
    - Manage(List/Enable/Disable) RHSM repositories to the Red Hat Subscription Management entitlement platform using the C(subscription-manager) command
version_added: "2.4"
author: "Giovanni Sciortino (giovannibattistasciortino@gmail.com)"
notes:
    - In order to manage rhsm repositories the system must be already registered to rhsm manually or using the ansible module redhat_subscription.
requirements:
    - subscription-manager
options:
    list:
        description:
          - List all/enabled/disabled repositories
        choices: [ "all", "enabled", "disabled" ]
        required: False
        default: None
    enable:
        description:
          - id of repositories to enable
          - To operate on several repositories this can accept a comma separated list or a list
        required: False
        default: None
    disable:
        description:
          - id of repositories to disable
          - To operate on several repositories this can accept a comma separated list or a list
        required: False
        default: None
    disable_first:
        description:
          - If disable_first is true, first the repositories defined in 'disable' list are disabled and later the
            repositories defined in 'enabled' are enabled
          - If disable_first is false, first the repositories defined in 'enable' list are enabled and later the
            repositories defined in 'disabled' are disabled
        required: False
        default: True

'''

EXAMPLES = '''
- name: List all RHSM repositories.
  redhat_repository:
    list: all

- name: List enabled RHSM repositories.
  redhat_repository:
    list: enabled

- name: Enable a RHSM repository
  redhat_subscription:
    enable: rhel-7-server-rpms

- name: Disable all RHSM repositories
  redhat_subscription:
    disable: rhel-7-server-rpms

- name: Enable all repository starting with rhel-6-server and disable the other
  redhat_repository:
    enable: rhel-6-server*
    disable: '*'
    disable_first: true

- name: Enable all available repository except the repository containing the string '-aus-' and '-eus-'
  redhat_repository:
    enable: '*'
    disable:
      - '*-aus-*'
      - '*-eus-*'
    disable_first: false
'''

RETURN = '''
rhsm_repositories:
    description: List of repositories
    returned: success
    type: list
'''

from ansible.module_utils.basic import AnsibleModule

import re
from fnmatch import fnmatch


def run_subscription_manager(module, arguments):
    # Execute subuscription-manager with arguments and manage common errors
    if module.get_bin_path('subscription-manager'):
        rhsm_bin = module.get_bin_path('subscription-manager')
    else:
        module.fail_json(msg='subscription-manager not found in PATH')

    rc, out, err = module.run_command(rhsm_bin + " " + " ".join(arguments))

    if rc == 1 and err == 'The password you typed is invalid.\nPlease try again.\n':
        module.fail_json(msg='subscription-manager must be run using root privileges')
    elif rc == 1:
        module.fail_json(msg='subscription-manager failed with the following error: %s' % err)
    else:
        return rc, out, err


def get_repository_list(module, list_parameter):
    # Generate rhsm repository list and return a list of dict
    if list_parameter == 'enabled':
        rhsm_arguments = ['repos', '--list-enabled']
    elif list_parameter == 'disabled':
        rhsm_arguments = ['repos', '--list-disabled']
    else:
        rhsm_arguments = ['repos', '--list']
    rc, out, err = run_subscription_manager(module, rhsm_arguments)

    skip_lines = ['+----------------------------------------------------------+',
                  '    Available Repositories in /etc/yum.repos.d/redhat.repo',
                  'There were no available repositories matching the specified criteria.',
                  'This system has no repositories available through subscriptions.']
    repo_id_re_str = r'Repo ID:   (.*)'
    repo_name_re_str = r'Repo Name: (.*)'
    repo_url_re_str = r'Repo URL:  (.*)'
    repo_enabled_re_str = r'Enabled:   (.*)'

    repo_id = ''
    repo_name = ''
    repo_url = ''
    repo_enabled = ''

    repo_result = []

    for line in out.split('\n'):
        if line in skip_lines:
            continue

        repo_id_re = re.match(repo_id_re_str, line)
        if repo_id_re:
            repo_id = repo_id_re.group(1)
            continue

        repo_name_re = re.match(repo_name_re_str, line)
        if repo_name_re:
            repo_name = repo_name_re.group(1)
            continue

        repo_url_re = re.match(repo_url_re_str, line)
        if repo_url_re:
            repo_url = repo_url_re.group(1)
            continue

        repo_enabled_re = re.match(repo_enabled_re_str, line)
        if repo_enabled_re:
            repo_enabled = repo_enabled_re.group(1)

            repo = {"id": repo_id, "name": repo_name, "url": repo_url, "enabled": True if repo_enabled == '1' else False}
            repo_result.append(repo)
    return repo_result


def repository_list(module, list_parameter):
    # Get rhsm repository list and format it for the user
    repo = get_repository_list(module, list_parameter)
    module.exit_json(changed=False, repositories=repo)


def repository_state_change(module, id, enable, disable, disable_first):
    enable = enable if enable else []
    disable = disable if disable else []

    current_repo_list = get_repository_list(module, 'all')
    if len(current_repo_list) == 0:
        module.fail_json(msg="This system has no repositories available through subscriptions.")

    # get repo to enable matching wildcards and check if repo are present
    matched_enable_repo = []
    for repoid in enable:
        for repo in current_repo_list:
            if fnmatch(repo['id'], repoid):
                matched_enable_repo.append(repo)
        if len(matched_enable_repo) == 0:
            module.fail_json(msg="'%s' is not valid repository ID" % repoid)

    # get repo to disable matching wildcards and check if repo are present
    matched_disable_repo = []
    for repoid in disable:
        for repo in current_repo_list:
            if fnmatch(repo['id'], repoid):
                matched_disable_repo.append(repo)
        if len(matched_disable_repo) == 0:
            module.fail_json(msg="'%s' is not valid repository ID" % repoid)

    # common_repo_id = interesection of repo id present in the lists matched_enable_repo and matched_disable_repo
    matched_disable_repo_id = set(x["id"] for x in matched_disable_repo)
    common_repo = [x for x in matched_enable_repo if x['id'] in matched_disable_repo_id]
    common_repo_id = set(x["id"] for x in common_repo)

    # give priority to enabled or disabled repository based on disable_first variable
    if disable_first:
        prio_matched_disable = [x for x in matched_disable_repo if x['id'] not in common_repo_id]
        prio_matched_enable = matched_enable_repo
    else:
        prio_matched_enable = [x for x in matched_enable_repo if x['id'] not in common_repo_id]
        prio_matched_disable = matched_disable_repo

    rhsm_arguments = ['repos']
    changed = False

    # define repositories disabled to enable
    for repo in prio_matched_enable:
        if not repo['enabled']:
            repo['enabled'] = True
            changed = True
            rhsm_arguments += ['--enable', repo['id']]

    # define repositories enabled to disable
    for repo in prio_matched_disable:
        if repo['enabled']:
            repo['enabled'] = True
            changed = True
            rhsm_arguments += ['--disable', repo['id']]

    repositories = []
    if prio_matched_enable:
        repositories.append(prio_matched_enable)
    if prio_matched_disable:
        repositories.append(prio_matched_disable)

    # execute subscription manager repos if check = False
    if not module.check_mode:
        rc, out, err = run_subscription_manager(module, rhsm_arguments)
    module.exit_json(changed=changed, repositories=repositories)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            list=dict(default=None,
                      choices=['all', 'enabled', 'disabled'],
                      required=False),
            enable=dict(type="list"),
            disable=dict(type="list"),
            disable_first=dict(type='bool', default=True, required=False)
        ),
        mutually_exclusive=[['list', 'enable'], ['list', 'disable']],
        required_one_of=[['list', 'enable', 'disable']],
        supports_check_mode=True
    )
    list_parameter = module.params['list']
    enable = module.params['enable']
    disable = module.params['disable']
    disable_first = module.params['disable_first']

    if list_parameter:
        repository_list(module, list_parameter)
    elif enable or disable:
        repository_state_change(module, id, enable, disable, disable_first)

if __name__ == '__main__':
    main()
