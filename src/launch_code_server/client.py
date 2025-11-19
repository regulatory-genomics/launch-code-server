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
    snippet = textwrap.dedent(
        f"""
        # >>> launch_code_server proxy >>>
        if [[ "$(hostname)" != *"login"* ]]; then
            export http_proxy=http://127.0.0.1:{local_port}
            export https_proxy=http://127.0.0.1:{local_port}
            export HTTP_PROXY=http://127.0.0.1:{local_port}
            export HTTPS_PROXY=http://127.0.0.1:{local_port}
            export ALL_PROXY=http://127.0.0.1:{local_port}
        fi
        # <<< launch_code_server proxy <<<
        """
    ).strip()

    command = textwrap.dedent(
        f"""
        bash -lc 'set -e
        rc="$HOME/.bashrc"
        if ! grep -Fq "# >>> launch_code_server proxy >>>" "$rc"; then
cat <<'EOF' >> "$rc"
{snippet}
EOF
        fi'
        """
    ).strip()

    conn.run(command, hide=True)

def ensure_proxy_tunnel(conn, node, login_host, target_host, target_port, local_port):
    """Start (if needed) the SSH tunnel that exposes the cluster HTTP proxy."""
    remote_script = textwrap.dedent(
        f"""
        set -e
        pattern="ssh -N -f -L {local_port}:{target_host}:{target_port} {login_host}"
        if pgrep -f "$pattern" >/dev/null 2>&1; then
            exit 0
        fi
        nohup ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -N -f -L {local_port}:{target_host}:{target_port} {login_host} >/tmp/launch_code_server_proxy.log 2>&1
        """
    ).strip()

    quoted = shlex.quote(remote_script)
    command = (
        f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {node} "
        f"'bash -lc {quoted}'"
    )
    conn.run(command, hide=True)

def connect_server(host, user, port=None):
    """ Establish a ssh connect between local and remote head node
    """
    conn = Connection(host, user=user, port=port)

    try:
        conn.open()
    except Exception:
        password = getpass.getpass(f"({user}@{host}) Password: ")
        conn.connect_kwargs = {'password': password}
        conn.open()

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

    if args.setup_proxy:
        logging.info("Ensuring proxy environment variables are configured...")
        ensure_proxy_env_config(conn, args.proxy_local_port)

    logging.info("Trying to reserve a remote compute node...")
    job_id, node, port = launch_compute(conn, args.partition, args.num_cpus, args.memory_per_cpu, args.compute_node, env_name=args.env_name)
    logging.info(f"A job (id={job_id}) has been reserved on node {node}")

    if args.setup_proxy:
        logging.info("Attempting to start proxy tunnel on compute node...")
        try:
            ensure_proxy_tunnel(
                conn,
                node,
                args.proxy_login_host,
                args.proxy_target_host,
                args.proxy_target_port,
                args.proxy_local_port,
            )
            logging.info("Proxy tunnel configured on compute node.")
        except Exception as err:
            logging.warning("Failed to configure proxy tunnel automatically: %s", err)
    with conn.forward_local(args.forward_port, 22, remote_host=node):
        logging.info(f"Setup port forwarding: localhost:{args.forward_port} => {node}:22")
        update_ssh_config(user, args.forward_port)

        logging.info("Press Ctrl+D to quit and shutdown the node...")
        patience = 3
        time.sleep(30)
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
