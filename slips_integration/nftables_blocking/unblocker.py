import threading
import time
from typing import Dict
from .exec_nftables_cmd import exec_nftables_command


class Unblocker:
    """
    nftables version of SLIPS unblocker
    Uses blocked4 set with automatic timeouts
    """

    def __init__(self, db, sudo, should_stop, logger, log_function):
        self.db = db
        self.sudo = sudo
        self.should_stop = should_stop
        self.logger = logger
        self.log = log_function
        self.unblocker_thread = threading.Thread(
            target=self._unblock_loop, daemon=True
        )
        self.unblocker_thread.start()
        self.unblock_requests = {}

    def unblock_request(self, ip: str, tw: int, flags: Dict):
        """Store unblock request for later processing"""
        self.unblock_requests[ip] = {"tw": tw, "flags": flags}

    def update_requests(self):
        """Process unblock requests for closed timewindows"""
        pass

    def _unblock_ip(self, ip: str, flags: Dict) -> bool:
        """Remove IP from blocked4 set"""
        blocked = exec_nftables_command(
            self.sudo,
            action="delete",
            ip_to_block=ip,
            flag="-s",
            options={}
        )
        
        if blocked:
            txt = f"Unblocked IP from nftables: {ip}"
            self.logger.info(txt)
            self.log(txt)
            return True
        return False

    def _unblock_loop(self):
        """Background thread that processes unblock requests"""
        while not self.should_stop():
            time.sleep(60)
            for ip in list(self.unblock_requests.keys()):
                request = self.unblock_requests.get(ip)
                if request:
                    self._unblock_ip(ip, request["flags"])
                    del self.unblock_requests[ip]
