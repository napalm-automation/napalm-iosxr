# -*- coding: utf-8 -*-
# Copyright 2017 Napalm Automation. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

from __future__ import unicode_literals

# import stdlib
import re
import copy
import socket

# import third party lib
from netmiko import ConnectHandler
from netmiko import __version__ as netmiko_version
from netmiko.ssh_exception import NetMikoTimeoutException
from netmiko.ssh_exception import NetMikoAuthenticationException

# import NAPALM base
import napalm_base.helpers
import napalm_iosxr.constants as C
from napalm_base.base import NetworkDriver
from napalm_base.utils import py23_compat
from napalm_base.exceptions import ConnectionException
from napalm_base.exceptions import MergeConfigException
from napalm_base.exceptions import ReplaceConfigException
from napalm_base.exceptions import CommandTimeoutException
from napalm_base.utils.py23_compat import text_type


class IOSXRSSHDriver(NetworkDriver):
    '''
    SSH-based driver for IOS-XR.
    '''

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        if optional_args is None:
            optional_args = {}
        self.port = optional_args.get('port', 22)
        self.lock_on_connect = optional_args.get('config_lock', False)
        # Netmiko possible arguments
        netmiko_argument_map = {
            'keepalive': 30,
            'verbose': False,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None
        }
        fields = netmiko_version.split('.')
        fields = [int(x) for x in fields]
        maj_ver, min_ver, bug_fix = fields
        if maj_ver >= 2:
            netmiko_argument_map['allow_agent'] = False
        elif maj_ver == 1 and min_ver >= 1:
            netmiko_argument_map['allow_agent'] = False
        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        for k, v in netmiko_argument_map.items():
            try:
                self.netmiko_optional_args[k] = optional_args[k]
            except KeyError:
                self.netmiko_optional_args[k] = v

    def open(self):
        try:
            self.device = ConnectHandler(device_type='cisco_xr',
                                         ip=self.hostname,
                                         port=self.port,
                                         username=self.username,
                                         password=self.password,
                                         **self.netmiko_optional_args)
            self.device.timeout = self.timeout
        except NetMikoTimeoutException as t_err:
            raise ConnectionException(t_err.args[0])
        except NetMikoAuthenticationException as au_err:
            raise ConnectionException(au_err.args[0])

    def close(self):
        if hasattr(self.device, 'remote_conn'):
            self.device.remote_conn.close()

    def is_alive(self):
        null = chr(0)
        try:
            # Try sending ASCII null byte to maintain
            #   the connection alive
            self.device.send_command(null)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure
            #   that the connection is unusable,
            #   hence return False.
            return {
                'is_alive': False
            }
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    def _send_command(self, command):
        '''
        Helper to send the command and get the output.
        '''
        output = self.device.send_command_timing(command,
                 delay_factor=self.netmiko_optional_args['global_delay_factor'],
                 max_loops=self.timeout/self.netmiko_optional_args['global_delay_factor'])
        # The output has a newline after the command prompt
        #   and another line with the timestamp.
        # e.g.:
        #
        # Tue Jul 18 11:53:32.372 UTC
        # For this reason, we need to strip the first two lines
        #   and return only what comes after.
        return '\n'.join(output.splitlines()[2:])

    def cli(self, commands):
        '''
        Execute raw CLI commands and return the output,
        as provided by the device.
        '''
        if not isinstance(commands, (list, tuple)):
            raise TypeError('Please enter a valid list of commands!')
        cli_output = {}
        for command in commands:
            response = self._send_command(command)
            cli_output[command] = response
        return cli_output
