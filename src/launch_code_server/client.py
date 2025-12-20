import argparse
import getpass
import logging
import shlex
import sys
import textwrap
import time
from io import StringIO
from os.path import expanduser

from fabric import Connection
from sshconf import read_ssh_config

def launch_compute(conn, partition, n_cpus, memory_per_cpu, node, timeout=300, env_name=None):
    partition = '' if partition is None else f'--partition {partition}'
    compute_node = '' if node is None else f'--compute_node {node}'
    output = exec(conn, f"vscode_server launch {partition} --number_of_cpus {n_cpus} --timeout {timeout} --memory_per_cpu {memory_per_cpu} {compute_node}", env_name=env_name)
    job_id, node, port = output.strip().split('\t')
    return (int(job_id), node, int(port))

def check_compute(conn, host, port, env_name=None):
    return exec(conn, f"vscode_server check --host {host} --port {port}", env_name=env_name).strip()

def ensure_proxy_env_config(conn, local_port):
    """Ensure the user's .bashrc exports proxy variables on compute nodes."""

    # 1. Define the marker we look for
    marker = "# >>> launch_code_server proxy >>>"

    # 2. Check if the configuration already exists
    check_cmd = f"grep -Fq '{marker}' ~/.bashrc"
    result = conn.run(check_cmd, warn=True, hide=True)

    # 3. If grep failed (exit code != 0), append the config
    if result.failed:
        logging.info("Appending proxy config to .bashrc...")

        lines_to_add = [
            f"\n{marker}",
            f"if [[ \"$(hostname)\" != *\"login\"* ]]; then",
            f"    export http_proxy=http://127.0.0.1:{local_port}",
            f"    export https_proxy=http://127.0.0.1:{local_port}",
            f"    export HTTP_PROXY=http://127.0.0.1:{local_port}",
            f"    export HTTPS_PROXY=http://127.0.0.1:{local_port}",
            f"    export ALL_PROXY=http://127.0.0.1:{local_port}",
            f"fi",
            f"# <<< launch_code_server proxy <<<\n"
        ]

        # Join lines
        block = "\n".join(lines_to_add)

        # Escape BOTH single quotes and double quotes for bash -c 'echo "..." ...'
        block_escaped = block.replace("'", "'\\''").replace('"', '\\"')

        # Run command
        conn.run(f"bash -c 'echo \"{block_escaped}\" >> ~/.bashrc'", hide=False)
    else:
        logging.info("Proxy config already present in .bashrc.")

def ensure_proxy_tunnel(conn, node, login_host, target_host, target_port, local_port):
    """Start (if needed) the SSH tunnel that exposes the cluster HTTP proxy."""
    # First check if tunnel is already running - look for actual LISTEN socket
    check_cmd = f"ss -tln | grep ':{local_port} '"
    result = conn.run(f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {node} '{check_cmd}'", hide=True, warn=True)
    
    # Check if we got actual output showing a listening socket
    if result.stdout.strip() and "LISTEN" in result.stdout:
        logging.info(f"Proxy tunnel already running on port {local_port}")
        return

    # Prompt for OTP locally
    otp = getpass.getpass(f"Enter OATH OTP for tunnel on {node}: ")
    
    logging.info("Starting proxy tunnel with provided OTP...")

    # Use SSH_ASKPASS with a helper script to handle OTP prompt non-interactively
    askpass_script = textwrap.dedent(f"""
        #!/bin/bash
        echo "{otp}"
    """).strip()

    setup_cmds = f"""
cat <<'EOF' > ~/.ssh_askpass_tunnel
{askpass_script}
EOF
chmod +x ~/.ssh_askpass_tunnel
export SSH_ASKPASS=~/.ssh_askpass_tunnel
export DISPLAY=:0  # SSH_ASKPASS needs DISPLAY set (even dummy) or setsid
setsid ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password -N -f -L {local_port}:{target_host}:{target_port} {login_host} < /dev/null
rm ~/.ssh_askpass_tunnel
    """

    full_cmd = f"ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {node} {shlex.quote(setup_cmds)}"
    
    conn.run(full_cmd, pty=True, warn=True)
    
    # Wait for tunnel to bind
    logging.info("Waiting for tunnel to establish...")
    time.sleep(3)
    
    # Verify tunnel is running
    verify_cmd = f"ss -tln | grep ':{local_port} '"
    result = conn.run(f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {node} '{verify_cmd}'", hide=True, warn=True)
    
    if result.stdout.strip() and "LISTEN" in result.stdout:
        logging.info(f"Proxy tunnel successfully established on {node}:{local_port}")
    else:
        logging.warning(f"Could not verify proxy tunnel on {node}:{local_port}")
        logging.warning(f"Manual check: ssh {node} 'ss -tln | grep {local_port}'")

def connect_server(host, user, port=None, gateway=None):
    """ Establish a ssh connect between local and remote head node
    """
    conn = Connection(host, user=user, port=port, gateway=gateway)

    try:
        conn.open()
    except Exception:
        password = getpass.getpass(f"({user}@{host}) Password: ")
        conn.connect_kwargs = {'password': password}
        conn.open()
    
    # Set keepalive on the transport after connection is established
    if conn.is_connected and conn.transport:
        conn.transport.set_keepalive(60)

    return conn

def exec(conn, code, env_name=None):
    """ Convenient wrapper to execute arbitrary python code on a remote
    """
    # If environment name is provided, activate micromamba environment before running command
    if env_name:
        # Use bash -c to properly handle environment activation
        # Preserve original PATH and add common system directories to ensure system commands like sbatch are available
        # Escape single quotes in the command by replacing them with '\''
        escaped_code = code.replace("'", "'\"'\"'")
        # Add common system paths to ensure sbatch and other system commands are found
        code = f"bash -c 'ORIG_PATH=\"$PATH\" && source $(micromamba shell hook --shell bash 2>/dev/null || echo ~/.bashrc) && micromamba activate {env_name} && export PATH=\"$PATH:/usr/bin:/bin:/usr/local/bin:/opt/slurm/bin:/usr/sbin:/sbin:$ORIG_PATH\" && {escaped_code}'"
    
    tmp = sys.stdout
    output = StringIO()
    sys.stdout = output
    conn.run(code, out_stream=sys.stdout, hide='err')
    sys.stdout = tmp
    return output.getvalue()

def get_user(hostname):
    """ Get login information from ssh configuration file
    """
    c = read_ssh_config(expanduser("~/.ssh/config"))
    if hostname in c.hosts():
        return c.host(hostname)['user']
    else:
        raise ValueError(f"Host {hostname} is not in your ssh configuration file")

def update_ssh_config(user, port):
    """ Update login information for the code server
    """
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
    parser.add_argument("--env", "--micromamba-env", type=str, dest="env_name", help="Micromamba environment name to activate before running commands.")
    parser.add_argument("--setup-proxy", action="store_true", help="Automatically configure HTTP proxy tunnel on compute nodes.")
    parser.add_argument("--proxy-login-host", type=str, default="login01", help="Login host used to reach the HTTP proxy.")
    parser.add_argument("--proxy-target-host", type=str, default="172.16.75.119", help="Internal HTTP proxy host.")
    parser.add_argument("--proxy-target-port", type=int, default=3128, help="Internal HTTP proxy port.")
    parser.add_argument("--proxy-local-port", type=int, default=9999, help="Local port on compute nodes that exposes the HTTP proxy.")
    parser.add_argument("--jump-host", type=str, help="Jump server address")
    parser.add_argument("--jump-port", type=int, default=22, help="Jump server port")
    parser.add_argument("--jump-user", type=str, help="User for jump server (defaults to target user if not specified)")
    args = parser.parse_args()

    destination = args.destination.split('@')
    if len(destination) == 1:
        host = destination[0]
        user = get_user(host)
    elif len(destination) == 2:
        user, host = destination
    else:
        raise ValueError("Invalid destination format. Please provide the hostname or username@hostname.")

    # Handle jump server connection
    gateway_conn = None
    if args.jump_host:
        logging.info(f"Connecting to jump server: {args.jump_host}:{args.jump_port}...")
        
        # Determine jump user (default to same as target user)
        j_user = args.jump_user if args.jump_user else user
        
        # Create the connection object for the jump server
        gateway_conn = Connection(args.jump_host, user=j_user, port=args.jump_port)
        
        # Authenticate to the Jump Server
        try:
            gateway_conn.open()
        except Exception:
            # Prompt for Jump Server password
            j_pass = getpass.getpass(f"({j_user}@{args.jump_host}) Jump Server Password: ")
            gateway_conn.connect_kwargs = {'password': j_pass}
            gateway_conn.open()
        
        # Set keepalive on the gateway connection
        if gateway_conn.is_connected and gateway_conn.transport:
            gateway_conn.transport.set_keepalive(60)
            
        logging.info("Jump server connection established.")

    # Connect to the actual HPC head node, passing the jump connection as the gateway
    if gateway_conn:
        logging.info(f"Connecting to target: {host} via gateway...")
    conn = connect_server(host, user, args.port, gateway=gateway_conn)

    if args.setup_proxy:
        logging.info("Ensuring proxy environment variables are configured...")
        ensure_proxy_env_config(conn, args.proxy_local_port)

    logging.info("Trying to reserve a remote compute node...")
    job_id, node, port = launch_compute(conn, args.partition, args.num_cpus, args.memory_per_cpu, args.compute_node, env_name=args.env_name)
    logging.info(f"A job (id={job_id}) has been reserved on node {node}")

    if args.setup_proxy:
        logging.info("Setting up proxy tunnel on compute node...")
        try:
            ensure_proxy_tunnel(
                conn,
                node,
                args.proxy_login_host,
                args.proxy_target_host,
                args.proxy_target_port,
                args.proxy_local_port,
            )
        except Exception as err:
            logging.warning(f"Failed to configure proxy tunnel: {err}")
            logging.info(f"You can manually run on {node}: ssh -N -L {args.proxy_local_port}:{args.proxy_target_host}:{args.proxy_target_port} {args.proxy_login_host}")
    with conn.forward_local(args.forward_port, 22, remote_host=node):
        logging.info(f"Setup port forwarding: localhost:{args.forward_port} => {node}:22")
        update_ssh_config(user, args.forward_port)

        logging.info("Press Ctrl+D to quit and shutdown the node...")
        patience = 3
        time.sleep(15)
        while True:
            try:
                response = check_compute(conn, node, port, env_name=args.env_name)
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
