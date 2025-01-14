import argparse
import pyslurm
import time

def main():
    main_parser = argparse.ArgumentParser(description="Reserve vscode-server.")
    subparsers = main_parser.add_subparsers(dest='command', help='Available commands', required=True)

    launch_parser = subparsers.add_parser('launch', help='Submit a job to Slurm with specified options.')
    launch_parser.add_argument("--partition", type=str, help="Partition to submit the job to.")
    launch_parser.add_argument("--number_of_cpus", type=int, default=1, help="Number of CPUs requested for the job.")
    launch_parser.add_argument("--memory_per_cpu", type=str, default="8G", help="Amount of memory requested for the job.")
    launch_parser.add_argument("--compute_node", type=str)
    launch_parser.add_argument("--timeout", type=int, default=300, help="Timeout.")

    check_parser = subparsers.add_parser('check', help='Check server status.')
    check_parser.add_argument("--host", type=str, required=True, help="Hostname.")
    check_parser.add_argument("--port", type=int, required=True, help="Port.")

    args = main_parser.parse_args()

    if args.command == 'launch':
        launch_server(args)
    if args.command == 'check':
        check_server(args)

def launch_server(args):
    import random

    random_port = random.randint(49152, 65535)
    job_desc = pyslurm.JobSubmitDescription(
        name="vscode-server",
        script=server_script(random_port, args.timeout),
        partitions=args.partition,
        time_limit='8:00:00',
        ntasks=args.number_of_cpus,
        memory_per_cpu=args.memory_per_cpu,
        standard_error="vscode_slurm.log",
        standard_output="vscode_slurm.log",
        required_nodes=args.compute_node,
    )

    job_id = job_desc.submit()

    job = pyslurm.Job(job_id).load(job_id)
    while job.state != 'RUNNING':
        time.sleep(1)
        job = job.load(job_id)

    print(f"{job_id}\t{job.allocated_nodes}\t{random_port}")


def check_server(args):
    import socket

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((args.host, args.port))
        message = client_socket.recv(1024)
        client_socket.close()
        print(f"SUCCESS: {message.decode()}")
    except socket.error as err:
        print(f"ERROR: {err}")

    except Exception as e:
        print(f"ERROR: {e}")

    finally:
        client_socket.close()


## String literals

def server_script(port, timeout=150):
    return f"""#!/usr/bin/env python
import socket
import select

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", {port}))
    server_socket.listen(5)
    server_socket.setblocking(0)  # Set socket to non-blocking mode
    print(f"Server listening on port {port}")

    try:
        while True:
            # Use select to wait for incoming connections with a timeout
            readable, _, _ = select.select([server_socket], [], [], {timeout})
            if readable:
                client_socket, addr = server_socket.accept()
                client_socket.send(b'Hello, thanks for connecting')
                client_socket.close()
            else:
                print(f"No clients connected for {timeout} seconds. Shutting down server.")
                break
    finally:
        server_socket.close()

start_server()
"""
