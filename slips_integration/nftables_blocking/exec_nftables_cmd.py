import subprocess


def exec_nftables_command(sudo: str, action, ip_to_block, flag, options):
    """
    Add or remove IP from nftables blocked4 set
    
    flag options:
      -s : to block traffic from source ip
      -d : to block to destination ip (both handled by set membership)
    action options:
      insert : add IP to blocked4 set
      delete : remove IP from blocked4 set
    """
    
    if action == "insert":
        nft_action = "add"
    elif action == "delete":
        nft_action = "delete"
    else:
        return False
    
    command = [
        sudo, "nft", nft_action, "element", 
        "inet", "home", "blocked4", 
        "{", ip_to_block, "}"
    ]
    
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False
