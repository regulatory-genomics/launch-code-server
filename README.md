# Installation

## Install server-side application (on the HPC)

1. Write the following information to your `~/.bashrc` file:

```
export SLURM_INCLUDE_DIR=/opt/slurm/include
export SLURM_LIB_DIR=/opt/slurm/lib
```

2. Execute `source ~/.bashrc`.
3. Clone the repository and use `pip install .[server]` to install.

## Install client-side application (on your computer)

1. clone the repository and use `pip install .` to install.

# Usage

1. Copy your ssh public key to the HPC server if you have not done so.
3. Open a terminal on your computer and type `launch_server USERNAME@HOSTNAME`.
4. Open vscode, and from the list of remote servers choose `vscode-server` to connect.
