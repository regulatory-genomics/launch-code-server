import argparse
import contextlib
import getpass
import logging
import os
import shlex
import subprocess
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
    marker = "# >>> launch_code_server proxy >>>"
    
    # Use bash -c with explicit non-interactive mode to bypass .bashrc issues
    # The -c flag runs a command string and doesn't source .bashrc by default
    
    # Test basic command execution first with non-interactive shell
    try:
        logging.info("Testing connection with simple command...")
        test_result = run_with_retry(conn, "/bin/bash -c 'echo test'", retries=2, hide=True)
        if not test_result.ok:
            logging.warning("Basic command test failed, connection may be unstable")
            logging.warning("Skipping proxy configuration - you may need to configure it manually")
            return
    except Exception as e:
        logging.error(f"Connection test failed: {e}")
        logging.warning("Skipping proxy configuration due to connection instability")
        logging.warning(f"You can manually add this to your ~/.bashrc on compute nodes:")
        logging.warning(f"  if [[ \"$(hostname)\" != *\"login\"* ]]; then")
        logging.warning(f"    export http_proxy=http://127.0.0.1:{local_port}")
        logging.warning(f"    export https_proxy=http://127.0.0.1:{local_port}")
        logging.warning(f"  fi")
        return  # Don't raise, just skip proxy setup
    
    # Check if configuration already exists (using non-interactive shell)
    check_cmd = f"/bin/bash -c 'grep -q \"{marker}\" ~/.bashrc 2>/dev/null'"
    result = run_with_retry(conn, check_cmd, retries=3, warn=True, hide=True)
    
    if result.ok:
        logging.info("Proxy config already present in .bashrc.")
        return
    
    logging.info("Appending proxy config to .bashrc...")
    
    # Create the configuration block
    config_block = f"""{marker}
if [[ "$(hostname)" != *"login"* ]]; then
    export http_proxy=http://127.0.0.1:{local_port}
    export https_proxy=http://127.0.0.1:{local_port}
    export HTTP_PROXY=http://127.0.0.1:{local_port}
    export HTTPS_PROXY=http://127.0.0.1:{local_port}
    export ALL_PROXY=http://127.0.0.1:{local_port}
fi
# <<< launch_code_server proxy <<<"""
    
    # Use printf to append (more reliable than cat with heredoc)
    # Escape the config block for printf
    escaped_block = config_block.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')
    append_cmd = f'/bin/bash -c "printf \"\\n{escaped_block}\\n\" >> ~/.bashrc"'
    
    try:
        run_with_retry(conn, append_cmd, retries=3, hide=False)
        logging.info("Proxy config successfully added to .bashrc.")
    except Exception as e:
        logging.error(f"Failed to update .bashrc: {e}")
        raise

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

# --- 🔵 Hack Start: Router Jump SSH Proxy Class ---
class SystemSSHConnection:
    """
    This is a proxy class that mimics Fabric's Connection object,
    but executes commands through a router jump host.
    
    Workflow: Mac -> Router -> (via Socket) -> HPC
    The router has an established SSH ControlMaster socket, so no OTP is needed.
    """
    def __init__(self, host, config, user=None, port=None, gateway=None, jump_host=None, jump_port=None, jump_user=None):
        # Get values from config dictionary (no longer hardcoded)
        self.router = config['router']       # e.g. gilberthan@172.16.210.201
        self.hpc_socket = config['socket']   # e.g. /tmp/hpc_socket
        self.hpc_host = config['hpc_host']   # e.g. hanlitian@172.16.78.132
        self.hpc_port = config['hpc_port']   # e.g. 12021
        
        # Keep original parameters for compatibility (though not used)
        self.host = host
        self.user = user
        self.port = port
        self.gateway = gateway
        self.jump_host = jump_host
        self.jump_port = jump_port
        self.jump_user = jump_user
        
        self.is_connected = True
        self.transport = type('Transport', (), {'set_keepalive': lambda self, x: None})()  # Bypass code checks
        self.connect_kwargs = {}
        self._stored_password = None

    def run(self, cmd, hide=False, warn=False, pty=False, **kwargs):
        """
        Core magic: Mac -> Router -> (via Socket) -> HPC
        We wrap cmd with shlex.quote to prevent special character errors
        """
        # Command executed on router: connect to HPC via socket and execute command
        # ssh -S socket -p port host "command"
        remote_cmd = f"ssh -S {self.hpc_socket} -p {self.hpc_port} {self.hpc_host} {shlex.quote(cmd)}"
        
        # Mac connects to router and executes the above command
        full_cmd = ["ssh", self.router, remote_cmd]
        
        try:
            # Use Popen if pty is needed
            if pty:
                proc = subprocess.Popen(
                    full_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate()
                return_code = proc.returncode
            else:
                res = subprocess.run(
                    full_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout = res.stdout
                stderr = res.stderr
                return_code = res.returncode
        except Exception as e:
            if not warn:
                raise e
            # Construct a fake failure result
            return type('Result', (), {
                'ok': False, 
                'stdout': '', 
                'stderr': str(e), 
                'return_code': 1
            })()

        # 🟢 Critical fix: Simulate Fabric's behavior
        # If out_stream parameter is provided (from exec function),
        # write stdout content to it so exec can capture the output.
        out_stream = kwargs.get('out_stream')
        if out_stream and stdout:
            out_stream.write(stdout)
            out_stream.flush()  # Ensure immediate write
        
        # Construct a fake successful Fabric result object
        class Result:
            def __init__(self, ok, stdout, stderr, return_code, command):
                self.ok = ok
                self.stdout = stdout
                self.stderr = stderr
                self.return_code = return_code
                self.command = command
        
        result = Result(return_code == 0, stdout, stderr, return_code, cmd)
        if not result.ok and not warn:
            raise Exception(f"SSH Command failed: {result.stderr}")
        return result

    def open(self):
        """Fake opening connection (actually reuses router's socket)"""
        self.is_connected = True
        pass

    def close(self):
        """Fake closing connection"""
        self.is_connected = False
        pass

    @contextlib.contextmanager
    def forward_local(self, local_port, remote_port, remote_host):
        """
        Port forwarding: Establish double-layer tunnel Mac -> Router -> HPC
        Since double-layer passwordless tunnel is complex, we use a simplified approach here.
        """
        logging.info(f"🔗 Tunneling: Mac:{local_port} -> Router -> HPC:{remote_host}:{remote_port}")
        
        # Use ProxyCommand to establish tunnel through router
        # Note: This may require SSH key authentication from router to Mac
        # Build port forwarding command through router
        # Method: Mac listens locally, forwards through router to HPC
        proxy_cmd = f"ssh -S {self.hpc_socket} -p {self.hpc_port} {self.hpc_host} -W {remote_host}:{remote_port}"
        ssh_cmd = [
            "ssh", "-N",
            "-L", f"{local_port}:{remote_host}:{remote_port}",
            "-o", f"ProxyCommand=ssh {self.router} {shlex.quote(proxy_cmd)}",
            self.hpc_host  # This is just a placeholder, actual connection goes through ProxyCommand
        ]
        
        logging.info(f"⚠️  Starting port forward (may require Router SSH key authentication)...")
        
        # Start background ssh forwarding process
        proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # Wait a bit to ensure tunnel is established
            time.sleep(2)
            # Check if process is still running
            if proc.poll() is not None:
                # Process has exited, read error message
                _, stderr = proc.communicate()
                logging.warning(f"⚠️  Port forwarding failed: {stderr.decode() if stderr else 'Unknown error'}")
                logging.warning(f"⚠️  Auto-forwarding disabled. You may need to manually tunnel if needed.")
                # Return an empty context manager
                @contextlib.contextmanager
                def dummy_forward():
                    yield
                return dummy_forward()
            yield
        finally:
            logging.info("🛑 Closing tunnel...")
            proc.terminate()
            proc.wait()
# --- 🔴 Hack End ---

def connect_server(host, user, port=None, gateway=None, router_config=None, jump_host=None, jump_port=None, jump_user=None):
    """
    Overridden: No longer creates Fabric connection, but returns our proxy object.
    This allows using the established SSH ControlMaster socket through router jump host, skipping OTP verification.
    """
    logging.info(f"🚀 Using Router Jump SSH to piggyback on: {host}")
    
    # Simple check to prevent missing configuration
    if not router_config or not router_config.get('router') or not router_config.get('hpc_host'):
        raise ValueError(
            "Missing Router/HPC config! Please set environment variables:\n"
            "  LCS_ROUTER (e.g. gilberthan@172.16.210.201)\n"
            "  LCS_HPC_HOST (e.g. hanlitian@172.16.78.132)\n"
            "Or use --router and --hpc-real-host command line arguments."
        )
    
    logging.info(f"   Mac -> Router ({router_config['router']}) -> HPC ({router_config['hpc_host']})")
    logging.info(f"   Socket: {router_config['socket']}")
    logging.info("   (Assuming you have established socket on router: ssh -M -S <socket> ...)")
    
    # Pass configuration to Connection class
    return SystemSSHConnection(
        host,
        router_config,
        user=user,
        port=port,
        gateway=gateway,
        jump_host=jump_host,
        jump_port=jump_port,
        jump_user=jump_user
    )

def run_with_retry(conn, command, retries=3, **kwargs):
    """Run a command with retry logic for connection issues."""
    for attempt in range(retries):
        try:
            return conn.run(command, **kwargs)
        except Exception as e:
            if attempt < retries - 1:
                logging.warning(f"Command failed (attempt {attempt + 1}/{retries}), retrying: {e}")
                time.sleep(2)
                # Try to reconnect
                try:
                    if not conn.is_connected:
                        # Ensure password is in connect_kwargs for reconnection
                        if hasattr(conn, '_stored_password') and conn._stored_password:
                            conn.connect_kwargs = {
                                'password': conn._stored_password,
                                'allow_agent': False,
                                'look_for_keys': False
                            }
                        conn.open()
                        # Reset keepalive after reconnection
                        if conn.is_connected and conn.transport:
                            conn.transport.set_keepalive(30)
                except Exception as reconnect_error:
                    logging.warning(f"Reconnection failed: {reconnect_error}")
            else:
                logging.error(f"Command failed after {retries} attempts")
                raise

def exec(conn, code, env_name=None):
    """ Convenient wrapper to execute arbitrary python code on a remote
    """
    if env_name:
        escaped_code = code.replace("'", "'\"'\"'")
        
        # We build a robust shell command that runs on the remote server:
        # 1. Start a Login Shell (bash -l) to load ~/.bashrc and PATH.
        # 2. Search for the package manager in priority order.
        # 3. Generate the activation hook using the correct syntax.
        shell_cmd = (
            f"bash -l -c '"
            # --- Discovery Logic ---
            f"MGR=\"\"; "
            f"for cmd in micromamba mamba conda; do "
            f"    if command -v $cmd &> /dev/null; then MGR=$cmd; break; fi; "
            f"done; "
            
            # --- Fallback to Environment Variables if 'command -v' failed ---
            f"if [ -z \"$MGR\" ]; then "
            f"    if [ -n \"$MAMBA_EXE\" ]; then MGR=\"$MAMBA_EXE\"; "
            f"    elif [ -n \"$CONDA_EXE\" ]; then MGR=\"$CONDA_EXE\"; "
            f"    else echo \"Error: No conda/mamba/micromamba found in PATH or env vars.\"; exit 127; fi; "
            f"fi; "
            # --- Activation Logic ---
            # Micromamba uses 'shell hook', Conda/Mamba use 'shell.bash hook'
            f"if [[ \"$MGR\" == *\"micromamba\"* ]]; then "
            f"    eval \"$($MGR shell hook --shell bash)\"; "
            f"else "
            f"    eval \"$($MGR shell.bash hook)\"; "
            f"fi && "
            
            f"$MGR activate {env_name} && "
            f"{escaped_code}'"
        )
        
        # Override the code to be executed
        code = shell_cmd
    
    tmp = sys.stdout
    output = StringIO()
    sys.stdout = output
    run_with_retry(conn, code, retries=3, out_stream=sys.stdout, hide='err')
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
    parser.add_argument("--timeout", type=int, default=3000, help="Server idle timeout in seconds (default: 300).")
    parser.add_argument("--setup-proxy", action="store_true", help="Automatically configure HTTP proxy tunnel on compute nodes.")
    parser.add_argument("--proxy-login-host", type=str, default="login01", help="Login host used to reach the HTTP proxy.")
    parser.add_argument("--proxy-target-host", type=str, default="172.16.75.119", help="Internal HTTP proxy host.")
    parser.add_argument("--proxy-target-port", type=int, default=3128, help="Internal HTTP proxy port.")
    parser.add_argument("--proxy-local-port", type=int, default=9999, help="Local port on compute nodes that exposes the HTTP proxy.")
    parser.add_argument("--jump-host", type=str, help="Jump server address")
    parser.add_argument("--jump-port", type=int, default=22, help="Jump server port")
    parser.add_argument("--jump-user", type=str, help="User for jump server (defaults to target user if not specified)")
    # Router jump configuration (can be set via environment variables)
    parser.add_argument("--router", type=str, default=os.environ.get("LCS_ROUTER"), 
                        help="Router SSH address (e.g. user@192.168.x.x, or set LCS_ROUTER env var)")
    parser.add_argument("--router-socket", type=str, default=os.environ.get("LCS_SOCKET", "/tmp/hpc_socket"), 
                        help="Path to the SSH socket on the router (or set LCS_SOCKET env var)")
    parser.add_argument("--hpc-real-host", type=str, default=os.environ.get("LCS_HPC_HOST"), 
                        help="Real HPC user@ip (e.g. user@172.16.x.x, or set LCS_HPC_HOST env var)")
    parser.add_argument("--hpc-real-port", type=str, default=os.environ.get("LCS_HPC_PORT", "22"), 
                        help="Real HPC SSH port (or set LCS_HPC_PORT env var)")
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
    # When using system SSH, jump host is automatically handled via -J option
    # No need to create separate connection, as system SSH will use ControlMaster
    if args.jump_host:
        logging.info(f"Using jump server: {args.jump_host}:{args.jump_port} (via system SSH)")
        j_user = args.jump_user if args.jump_user else user
    else:
        j_user = None

    # Prepare router configuration dictionary
    router_config = {
        'router': args.router,
        'socket': args.router_socket,
        'hpc_host': args.hpc_real_host,
        'hpc_port': args.hpc_real_port
    }
    
    # Connect to the actual HPC head node
    # Using system SSH, will automatically utilize ControlMaster connection
    conn = connect_server(
        host, 
        user, 
        args.port,
        router_config=router_config,
        jump_host=args.jump_host,
        jump_port=args.jump_port,
        jump_user=j_user
    )
    
    # Wait for connection to stabilize before running commands
    logging.info("Waiting for connection to stabilize...")
    time.sleep(2)

    if args.setup_proxy:
        logging.info("Ensuring proxy environment variables are configured...")
        ensure_proxy_env_config(conn, args.proxy_local_port)

    logging.info("Trying to reserve a remote compute node...")
    job_id, node, port = launch_compute(conn, args.partition, args.num_cpus, args.memory_per_cpu, args.compute_node, timeout=args.timeout, env_name=args.env_name)
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
