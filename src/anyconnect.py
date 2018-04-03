##################################################################################################
# Author: Oli Kondrashov
# Project: Alfred AnyConnect workflow
# Module: Automation script
# License: TBD

import sys
import subprocess
import os
import argparse

from workflow import Workflow3
from workflow.workflow import Settings, KeychainError, PasswordNotFound
from workflow.notify import notify

from config import *
from va_token import *

##################################################################################################
# Global objects
cfg = None
log = None
tok = None

##################################################################################################
# Utilities
def send_notification(title, body):
    return notify(title, body)

def calculate_key():
    func_name = calculate_key.__name__

    secret = cfg.get_field('secret')
    if len(secret) is 0:
        log.error("%s no secret", func_name)
        return None

    return tok.calculate_key(secret)

##################################################################################################
# Custom actions
def generate_token(wf):
    return None

def generate_key(wf):
    func_name = generate_key.__name__

    key = calculate_key()
    if key is None:
        log.error("%s failed to calculate_key", func_name)
        send_notification('Error', 'Failed to calculate key')

    wf.add_item(title='Copy to clipboard',
                    arg=key,
                    valid=True)

    return send_notification('Key is generated', key)

def set_username(wf, username):
    func_name = set_username.__name__

    if cfg.set_field('username', username) is False:
        log.error("%s failed to set username[%s]", func_name, username)
        send_notification('Error', 'Failed to set username')
        return -1

    return send_notification('Username configured', username)

def get_username():
    func_name = get_username.__name__
    return cfg.get_field('username')

def set_pin(wf, pin):
    func_name = set_pin.__name__

    try:
        wf.save_password('olikon_vpn_wf', pin)
    except KeychainError:
        log.error("%s failed to save pin", func_name)
        return -1

    return send_notification('Pin configured', '...') # :-)

def get_pin(wf):
    func_name = get_pin.__name__

    pin = None

    try:
        pin = wf.get_password('olikon_vpn_wf')
    except PasswordNotFound:
        log.error("%s failed to get pin", func_name)

    return pin

def set_domain(wf, domain):
    func_name = set_domain.__name__

    if cfg.set_field('domain', domain) is False:
        log.error("%s failed to set domain[%s]", func_name, domain)
        send_notification('Error', 'Failed to set domain')
        return -1

    return send_notification('Domain configured', domain)

def get_domain():
    func_name = get_domain.__name__
    return cfg.get_field('domain')

def connect(wf):
    func_name = connect.__name__

    credentials = "printf '0\\n" + get_username() + "\\n" + get_pin(wf) + calculate_key() + "\\ny'" # group + username + pin + 6-digit
    vpn_cmd = "/opt/cisco/anyconnect/bin/vpn -s connect '" + get_domain() + "'"
    cmd = credentials + " | " + vpn_cmd

    log.debug("%s command is %s", func_name, cmd)

    #TODO: Add error handling, when Cisco AnyConnect fails to connect we need to show error

    subprocess.Popen(cmd,
                     shell=True,
                     executable="/bin/bash",
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE).communicate()

    ret = send_notification('VPN', 'Connected')

    gui_cmd = "open -a \"/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app\""
    cmd = gui_cmd

    subprocess.Popen(cmd,
                     shell=True,
                     executable="/bin/bash",
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE).communicate()

    return ret

def disconnect(wf):
    func_name = disconnect.__name__

    cmd = "/opt/cisco/anyconnect/bin/vpn -s disconnect"

    log.debug("%s command is %s", func_name, cmd)

    subprocess.Popen(cmd,
                     shell=True,
                     executable="/bin/bash",
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE).communicate()

    return send_notification('VPN', 'Disconnected')

def main(wf):
    func_name = main.__name__
    log.info(">> %s(%s)", func_name, wf.args)

    token = cfg.get_field('id')
    log.info("%s token is %s", func_name, token)

    ##################################################################################################
    # Check for updates
    # TODO: implement

    ##################################################################################################
    # Parse script arguments
    parser = argparse.ArgumentParser()

    parser.add_argument('--generate-token', dest='generate_token', action='store_true', default=False, help='Generates OTP token')
    parser.add_argument('--generate-key', dest='generate_key', action='store_true', default=False, help='Generates 6-digits key')
    parser.add_argument('--set-username', dest='username', nargs='?', default=None)
    parser.add_argument('--set-pin', dest='pin', nargs='?', default=None)
    parser.add_argument('--set-domain', dest='domain', nargs='?', default=None)
    parser.add_argument('--connect', dest='connect', action='store_true', default=False, help='Connect to VPN')
    parser.add_argument('--disconnect', dest='disconnect', action='store_true', default=False, help='Disconnect from VPN')

    # Parsing actual script arguments
    args = parser.parse_args(wf.args)
    log.debug("Parsed args: %s", args)

    res = 0

    if args.generate_token is True:
        res = generate_token(wf)

    if args.generate_key is True:
        res = generate_key(wf)

    if args.username is not None:
        res = set_username(wf, args.username)

    if args.pin is not None:
        res = set_pin(wf, args.pin)

    if args.domain is not None:
        res = set_domain(wf, args.domain)

    if args.connect is True:
        res = connect(wf)

    if args.disconnect is True:
        res = disconnect(wf)

    wf.send_feedback()

    log.info("<< %s", func_name)
    return res

if __name__ == u"__main__":
    wf = Workflow3()
    cfg = config(wf)
    log = wf.logger
    tok = va_token()

    sys.exit(wf.run(main))
