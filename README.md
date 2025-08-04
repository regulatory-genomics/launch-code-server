# Installation

## Install server-side application (on the HPC)

```shell
pip install 'git+https://github.com/regulatory-genomics/launch-code-server.git#egg=launch-code-server'
```

## Install client-side application (on your computer)

```shell
pip install 'git+https://github.com/regulatory-genomics/launch-code-server.git#egg=launch-code-server'[client]
```

# Usage

1. Copy your ssh public key to the HPC server if you have not done so.
   You still need to do this even if you cannot use the public key to login to the HPC server.
3. Open a terminal on your computer and type `launch_server USERNAME@HOSTNAME`.
4. Open vscode, and from the list of remote servers choose `vscode-server` to connect.
