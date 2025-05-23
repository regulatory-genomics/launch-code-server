import argparse
import getpass
from fabric import Connection
from sshconf import read_ssh_config
from os.path import expanduser
from io import StringIO
import sys
import time
import logging

def exec(conn, code):
    tmp = sys.stdout
    output = StringIO()
    sys.stdout = output
    conn.run(code, out_stream=sys.stdout, hide='err')
    sys.stdout = tmp
    return output.getvalue()

def launch_compute(conn, partition, n_cpus, memory_per_cpu, node, timeout=300):
    partition = '' if partition is None else f'--partition {partition}'
    compute_node = '' if node is None else f'--compute_node {node}'
    output = exec(conn, f"vscode_server launch {partition} --number_of_cpus {n_cpus} --timeout {timeout} --memory_per_cpu {memory_per_cpu} {compute_node}")
    job_id, node, port = output.strip().split('\t')
    return (int(job_id), node, int(port))

def check_compute(conn, host, port):
    return exec(conn, f"vscode_server check --host {host} --port {port}").strip()

def connect_server(host, user, port=None):
    conn = Connection(host, user=user, port=port)

    try:
        conn.open()
    except Exception:
        password = getpass.getpass(f"({user}@{host}) Password: ")
        conn.connect_kwargs = {'password': password}
        conn.open()

    return conn

def get_user(hostname):
    c = read_ssh_config(expanduser("~/.ssh/config"))
    if hostname in c.hosts():
        return c.host(hostname)['user']
    else:
        raise ValueError(f"Host {hostname} is not in your ssh configuration file")

def update_ssh_config(user, port):
    host = 'vscode-server'
    path = expanduser("~/.ssh/config")
    c = read_ssh_config(path)

    update = True
    if host in c.hosts():
        h = c.host(host)
        if h['hostname'] == 'localhost' and h['user'] == user and h['port'] == port:
            update = False
        else:
            c.remove(host)

    if update:
        c.add(
            host, Hostname="localhost", User=user, Port=port,
            StrictHostKeyChecking="no", UserKnownHostsFile="/dev/null",
        )
        c.save()

def main():
    logging.basicConfig(
        stream=sys.stderr,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO, 
    )

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Reserve vscode remote server")
    parser.add_argument('destination', type=str, help="Address of the HPC headnode")
    parser.add_argument('-p', "--port", type=int, help="Port to connect to") 
    parser.add_argument('-f', "--forward-port", type=int, default=2222, help="Local port to forward to remote port") 
    parser.add_argument("--partition", type=str, help="Partition to submit the job to.")
    parser.add_argument("--compute-node", type=str, help="Hostname of compute node to reserve.")
    parser.add_argument("-n", "--num-cpus", type=int, default=1, help="Number of CPUs requested for the job.")
    parser.add_argument("-m", "--memory_per_cpu", type=str, default="8G", help="Memory per cpu requested for the job.")
    args = parser.parse_args()

    destination = args.destination.split('@')
    if len(destination) == 1:
        host = destination[0]
        user = get_user(host)
    elif len(destination) == 2:
        user, host = destination
    else:
        raise ValueError("Invalid destination format. Please provide the hostname or username@hostname.")

    conn = connect_server(host, user, args.port)

    logging.info("Trying to reserve a remote compute node...")
    job_id, node, port = launch_compute(conn, args.partition, args.num_cpus, args.memory_per_cpu, args.compute_node)
    logging.info(f"A job (id={job_id}) has been reserved on node {node}")
    with conn.forward_local(args.forward_port, 22, remote_host=node):
        logging.info(f"Setup port forwarding: localhost:{args.forward_port} => {node}:22")
        update_ssh_config(user, args.forward_port)

        logging.info("Press Ctrl+D to quit and shutdown the node...")
        patience = 3
        time.sleep(30)
        while True:
            try:
                response = check_compute(conn, node, port)
                if not response.startswith('SUCCESS'):
                    logging.error(f"An error occurred during the communication with the remote server: {response}")
                    sys.exit(1)
                else:
                    patience = 3
            except Exception as err:
                if patience <= 0:
                    logging.error(f"Fail to connect to the server: Unexpected {err=}, {type(err)=}")
                    sys.exit(1)
                else:
                    patience -= 1
            time.sleep(15)
