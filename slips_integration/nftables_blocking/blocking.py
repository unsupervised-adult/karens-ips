# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-FileCopyrightText: 2025 Karen's IPS (nftables adaptation)
# SPDX-License-Identifier: GPL-2.0-only
import platform
import sys
import os
import shutil
import json
import subprocess
from typing import Dict
import time
from threading import Lock

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.slips_utils import utils
from .exec_nftables_cmd import exec_nftables_command
from modules.blocking.unblocker import Unblocker


class Blocking(IModule):
    """nftables-based blocking module for Karen's IPS
    Uses the 'blocked4' set in the 'inet home' table"""

    name = "Blocking"
    description = "Block malicious IPs using nftables blocked4 set"
    authors = ["Sebastian Garcia, Alya Gomaa, Karen's IPS"]

    def init(self):
        self.c1 = self.db.subscribe("new_blocking")
        self.c2 = self.db.subscribe("tw_closed")
        self.channels = {
            "new_blocking": self.c1,
            "tw_closed": self.c2,
        }
        if platform.system() == "Darwin":
            self.print("Mac OS blocking is not supported yet.")
            sys.exit()

        self.firewall = self._determine_linux_firewall()
        self.sudo = utils.get_sudo_according_to_env()
        self._verify_nftables_setup()
        self.blocking_log_path = os.path.join(self.output_dir, "blocking.log")
        self.blocking_logfile_lock = Lock()
        try:
            open(self.blocking_log_path, "w").close()
        except FileNotFoundError:
            pass

    def log(self, text: str):
        """Logs the given text to the blocking log file"""
        with self.blocking_logfile_lock:
            with open(self.blocking_log_path, "a") as f:
                now = time.time()
                human_readable_datetime = utils.convert_ts_format(
                    now, utils.alerts_format
                )
                f.write(f"{human_readable_datetime} - {text}\n")

    def _determine_linux_firewall(self):
        """Returns nftables as the firewall"""
        if shutil.which("nft"):
            return "nftables"
        else:
            self.print(
                "nftables is not installed. Blocking module is quitting."
            )
            sys.exit()

    def _get_cmd_output(self, command):
        """Executes a command and returns the output"""
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode("utf-8")

    def _verify_nftables_setup(self):
        """Verify that the blocked4 set exists in nftables"""
        self.print('Verifying nftables blocked4 set exists', 6, 0)
        
        check_cmd = f"{self.sudo} nft list set inet home blocked4"
        result = subprocess.run(
            check_cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if result.returncode != 0:
            self.print(
                "ERROR: nftables 'blocked4' set not found. "
                "Ensure Karen's IPS nftables configuration is loaded.",
                0, 1
            )
            sys.exit()
        else:
            self.print("nftables blocked4 set verified", 6, 0)

    def _is_ip_already_blocked(self, ip) -> bool:
        """Checks if ip is already in the blocked4 set"""
        command = f"{self.sudo} nft list set inet home blocked4"
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        result = result.stdout.decode("utf-8")
        return ip in result

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is RFC1918 private address or other non-routable"""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return False
            
            # RFC1918 private ranges
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            
            # Loopback
            if octets[0] == 127:
                return True
            
            # Link-local
            if octets[0] == 169 and octets[1] == 254:
                return True
            
            # Multicast and reserved
            if octets[0] >= 224:
                return True
                
            return False
        except (ValueError, IndexError):
            return False

    def _block_ip(self, ip_to_block: str, flags: Dict[str, str]) -> bool:
        """
        Block IP by adding it to the nftables blocked4 set
        The set automatically blocks bidirectional traffic on the bridge
        """

        if self.firewall != "nftables":
            return False

        if not isinstance(ip_to_block, str):
            return False
        
        if self._is_private_ip(ip_to_block):
            txt = f"Skipping private/local IP: {ip_to_block}"
            self.print(txt, 3, 0)
            return False

        if self._is_ip_already_blocked(ip_to_block):
            return False

        blocked = exec_nftables_command(
            self.sudo,
            action="insert",
            ip_to_block=ip_to_block,
            flag="-s",
            options={}
        )
        
        if blocked:
            txt = f"Blocked IP in nftables: {ip_to_block}"
            self.print(txt)
            self.log(txt)
            self.db.set_blocked_ip(ip_to_block)
            return True
        else:
            txt = f"Failed to block IP in nftables: {ip_to_block}"
            self.print(txt, 0, 1)
            self.log(txt)
            return False

    def shutdown_gracefully(self):
        self.unblocker.unblocker_thread.join(30)
        if self.unblocker.unblocker_thread.is_alive():
            self.print("Problem shutting down unblocker thread.")

    def pre_main(self):
        self.unblocker = Unblocker(
            self.db, self.sudo, self.should_stop, self.logger, self.log
        )

    def main(self):
        if msg := self.get_msg("new_blocking"):
            data = json.loads(msg["data"])
            ip = data.get("ip")
            tw: int = data.get("tw")
            block = data.get("block")

            flags = {
                "from_": data.get("from"),
                "to": data.get("to"),
                "dport": data.get("dport"),
                "sport": data.get("sport"),
                "protocol": data.get("protocol"),
            }
            if block:
                self._block_ip(ip, flags)
            self.unblocker.unblock_request(ip, tw, flags)

        if msg := self.get_msg("tw_closed"):
            profileid_tw = msg["data"].split("_")
            twid = profileid_tw[-1]
            if self.last_closed_tw != twid:
                self.last_closed_tw = twid
                self.unblocker.update_requests()
