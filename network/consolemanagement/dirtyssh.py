#!/usr/bin/env python

# (c) 2016, Mohamed Amine Ben Asker
#               Twitter @asker_amine, Github yurilaaziz
#

DOCUMENTATION = '''
---
module: dirtyssh
author: Amine Ben Asker, @asker_amine
version_added: "0.1.0"
short_description: Execute commands on device over an old management console and save the output locally
description:
    - Execute command on device over management console and save the output locally on a file
requirements:
    - paramiko
options:
    host:
        description:
            - Set to {{ inventory_hostname }}
        required: true
    user:
        description:
            - Login username
        required: false
        default: $USER
    passwd:
        description:
            - Login password
        required: false
        default: empty 
    port:
        description:
            - port number to use when connecting to the device
        required: false
        default: 22
    timeout:
        description:
            - Set the ssh transport IO timeout. Set this value to accommodate Cli
              commands that might take longer than the default timeout interval.
        required: false
        default: "10"
    commands:
        description:
            - CLI command to execute on the host. Use new line separator for multiple command
        required: false
    waittime:
        description:
            - Set the wait time between executing commands. Set this value to accommodate Cli
              commands that might take longer than the timeout interval.
        required: false
        default: "10"
    logfile:
        description:
            - Path on the local server where the progress status is logged
              for debugging purposes
        required: false
        default: None
    dest:
        description:
            - Path to the local server directory where cli output will
              be saved.
        required: true
        default: None
'''

EXAMPLES = '''
# send dirty commands from file over console server 
- dirtyssh:
    host: "{{ inventory_hostname }}"
    user: "root"
    passwd: ""
    port: 7002
    commands: "{{ lookup('file','/tmp/commands.txt') }}"
    dest: "/tmp/outputfile.txt"
    waittime: 4

# send dirty command over console server 
- dirtyssh:
    host: "{{ inventory_hostname }}"
    user: "root"
    passwd: ""
    port: 7002
    commands: "show ip route"
    dest: "/tmp/outputfile.txt"
    waittime: 4

'''

import logging
import time 



'''
Timeout Error Handler 
'''

class TimeoutError(Exception):
    pass

def timeout(seconds=18, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator


def main():

    module = AnsibleModule(
        argument_spec=dict(host=dict(required=True, default=None),  # host or ipaddr
                           user=dict(required=False, default=os.getenv('USER')),
                           passwd=dict(required=False, default=None),
                           port=dict(required=False, type='int', default=22),
                           dest=dict(required=False, default=''),
                           timeout=dict(required=False, type='int', default=10),
                           waittime=dict(required=False, type='int', default=2),
                           commands=dict(required=False, default=''),
                           logfile=dict(required=False, default=None)
                           ),
        supports_check_mode=True)

    args = module.params

    try:
        import paramiko
    except ImportError as ex:
        module.fail_json(msg='ImportError: %s' % ex.message)


    logfile = args['logfile']
    if logfile is not None:
        logging.basicConfig(filename=logfile, level=logging.INFO,
                            format='%(asctime)s:%(name)s:%(message)s')
        logging.getLogger().name = 'CONFIG:' + args['host']

    logging.info("connecting to host: {0}@{1}:{2}".format(args['user'], args['host'], args['port']))


    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy( paramiko.AutoAddPolicy() )

    try:
        ssh.connect( args['host'], port = int(args['port']), username = args['user'], password = args['passwd'])
        channel = ssh.invoke_shell()
        channel.settimeout(args['timeout'])
    except Exception as err:
        msg = 'unable to connect to {0}: {1}'.format(args['host'], str(err))
        logging.error(msg)
        module.fail_json(msg=msg)
        # --- UNREACHABLE ---

    cli_output=""
    cmd_array=args['commands'].split('\n')

    for cmd in cmd_array:
        logging.info('Exec {0}'.format(cmd))
        try:
            channel.send(cmd + '\n')
            time.sleep(int(args['waittime']))
            data = channel.recv(2048)
            time.sleep(int(args['waittime']))
            logging.info('<<< {1} >>>'.format(cmd, data.strip()))
        except Exception as err:
            msg = 'unable to exec {0}: {1}'.format(cmd, str(err))
            logging.error(msg)
            ssh.close()
            module.fail_json(msg=msg)
        cli_output+= data + "\n"
    ssh.close()
    if args['dest']!='' :
        with open(args['dest'], 'w+') as outputfile:
            outputfile.write(cli_output)

    module.exit_json()

from ansible.module_utils.basic import *
main()
