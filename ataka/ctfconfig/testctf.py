import json
import requests
    
from pwn import *

from ataka.common.flag_status import FlagStatus

### EXPORTED CONFIG

# Ataka Host Domain / IP
ATAKA_HOST = "10.67.1.3:8001"

# Default targets for atk runlocal
RUNLOCAL_TARGETS = [
    # NOP Team
    "10.67.3.2",
]

# IPs that are always excluded from attacks. These can be included in runlocal with --ignore-exclusions
# These still get targets with flag ids, they're just never (automatically) attacked
STATIC_EXCLUSIONS = {'10.2.1.1'}

ROUND_TIME = 30

# format: regex, group where group 0 means the whole regex
FLAG_REGEX = r"FAUST_[A-Za-z0-9/+]{32}", 0

# Maximum list length for submit_flags()
FLAG_BATCHSIZE = 500

# Minimum wait in seconds between each call of submit_flags()
FLAG_RATELIMIT = 3

# When the CTF starts
START_TIME = 1781416800 + 1  # Sun Jul 16 2023 09:00:00 GMT+0200 (Central European Summer Time)

### END EXPORTED CONFIG

EDITION = 2023

FLAGID_URL = f"http://10.67.1.1/competition/teams.json"


def get_targets():
    no_flagid_services = set()

    teams = requests.get(FLAGID_URL).json()

    team_ids = teams['teams']
    flag_ids = teams['flag_ids']

    ## A generic solution for just a single vulnbox:
    default_targets = {service: {str(i): [] for i in team_ids} for service in no_flagid_services} | {service: {} for service in flag_ids.keys()}

    targets = {
        service: [
            {
                "ip": f"10.67.1.2",
                "extra": json.dumps(info),
            }
            for i, info in (default_targets[service] | service_info).items()
        ]
        for service, service_info in ({service: {} for service in no_flagid_services} | flag_ids).items()
    }

    return targets


def submit_flags(flags):
    # TODO for next time: exchange with long-living socket, possibly async API
    results = []
    try:
        HEADER = b"\nOne flag per line please!\n\n"
        server = remote("10.67.1.1", 6666, timeout=2)
        server.recvuntil(HEADER, timeout=5)
        for flag in flags:
            server.sendline(flag.encode())
            response = server.recvline(timeout=2)
            if b" INV" in response:
               results += [FlagStatus.INVALID]
            elif b' OLD' in response:
                results += [FlagStatus.INACTIVE]
            elif b' OK' in response:
                results += [FlagStatus.OK]
            elif b' OWN' in response:
                results += [FlagStatus.OWNFLAG]
            elif b' DUP' in response:
                results += [FlagStatus.DUPLICATE]
            else:
                results += [FlagStatus.ERROR]
                print(f"Invalid response: {response}")
        server.close()
    except Exception as e:
        print(f"Exception: {e}", flush=True)
        results += [FlagStatus.ERROR for _ in flags[len(results):]]

    return results
