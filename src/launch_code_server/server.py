import argparse
import time
import tempfile
import os
import subprocess

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
    script_content = server_script(random_port, args.timeout)

    # Write the server script to a temporary file
    script_fd, script_path = tempfile.mkstemp(suffix='.sh', text=True)
    try:
        os.write(script_fd, script_content.encode())
        os.close(script_fd)
        os.chmod(script_path, 0o755)

        # Build the sbatch command
        sbatch_cmd = [
            "sbatch",
            "--job-name=vscode-server",
            "--time=8:00:00",
            f"--error=vscode_slurm.log",
            f"--output=vscode_slurm.log"
        ]

        if args.partition:
            sbatch_cmd.append(f"--partition={args.partition}")
        if args.number_of_cpus:
            sbatch_cmd.append(f"--ntasks={args.number_of_cpus}")
        if args.memory_per_cpu:
            sbatch_cmd.append(f"--mem-per-cpu={args.memory_per_cpu}")
        if args.compute_node:
            sbatch_cmd.append(f"--nodelist={args.compute_node}")

        sbatch_cmd.append(script_path)

        # Submit the job
        result = subprocess.run(
            sbatch_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )

        # Parse job ID from sbatch output
        job_id = None
        for word in result.stdout.split():
            if word.isdigit():
                job_id = word
                break
        if not job_id:
            raise RuntimeError("Could not parse job ID from sbatch output")

        # Wait for the job to enter RUNNING state
        while True:
            squeue_cmd = [
                "squeue",
                "-j", job_id,
                "--format=%T",
                "--noheader"
            ]
            result = subprocess.run(
                squeue_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            state = result.stdout.strip()
            if state == "RUNNING":
                break
            time.sleep(1)

        # Get the allocated nodes
        squeue_cmd = [
            "squeue",
            "-j", job_id,
            "--format=%N",
            "--noheader"
        ]
        result = subprocess.run(
            squeue_cmd,
            stdout=subprocess.PIPE,
            text=True,
            check=True
        )
        allocated_nodes = result.stdout.strip()

        # Output the job ID, allocated nodes, and port
        print(f"{job_id}\t{allocated_nodes}\t{random_port}")

    finally:
        # Clean up the temporary script file
        if os.path.exists(script_path):
            os.remove(script_path)

def check_server(args):
    import socket

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((args.host, args.port))
        message = client_socket.recv(1024)
        client_socket.close()
        print(f"SUCCESS: {message.decode('utf-8')}")
    except socket.error as err:
        print(f"ERROR: {err}")

    except Exception as e:
        print(f"ERROR: {e}")

    finally:
        client_socket.close()


## String literals

def server_script(port, timeout=150):
    return f"""#!/usr/bin/env python
from __future__ import print_function
import socket
import select

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", {port}))
    server_socket.listen(5)
    server_socket.setblocking(0)  # Set socket to non-blocking mode
    print("Server listening on port {port}")

    try:
        while True:
            readable, _, _ = select.select([server_socket], [], [], {timeout})
            if readable:
                client_socket, addr = server_socket.accept()
                client_socket.send('Hello, thanks for connecting'.encode('utf-8'))
                client_socket.close()
            else:
                print("No clients connected for {timeout} seconds. Shutting down server.")
                break
    finally:
        server_socket.close()

start_server()
"""
