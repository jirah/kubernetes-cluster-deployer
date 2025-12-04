☸️ Vanilla K8s Manager & Deployer

Vanilla K8s Manager is a lightweight, single-file GUI tool designed to bootstrap, manage, and monitor "Vanilla" Kubernetes clusters on bare-metal servers or VMs.

Built with Python and Streamlit, it simplifies the complex process of setting up kubeadm clusters into a few clicks, offering a unified interface for cluster creation, worker node joining, GitOps-based application deployment, and real-time monitoring.

<img width="1268" height="1136" alt="image" src="https://github.com/user-attachments/assets/2e56a972-2935-4dbb-bd48-e92ea8a2711c" />
<img width="1256" height="1134" alt="image" src="https://github.com/user-attachments/assets/98531d7f-7c09-4ad8-92e9-2439b805175d" />


✨ Key Features

1. 🛠️ Cluster Bootstrap & Management

Automated Master Setup: One-click installation of Kubernetes Control Plane components (kubeadm, kubelet, kubectl, containerd, flannel CNI) on a fresh Linux VM.

Smart OS Detection: Automatically detects and adapts to Debian/Ubuntu (apt), RHEL/Rocky/CentOS (dnf), and SUSE (zypper). Includes specific fixes for Debian Trixie/Sid.

Worker Node Onboarding: Generates ready-to-use Cloud-Init (user-data.yaml) and Bash (worker-setup.sh) scripts to easily join worker nodes to the cluster.

Live Node Status: View real-time status of all nodes, including hardware specs (CPU/RAM formatted in GiB) and kernel versions.

Node Management: Ability to detach worker nodes directly from the UI.

2. 🛍️ Marketplace & GitOps

One-Click App Store: Instantly deploy complex Data & Analytics stacks using FluxCD.

Supported Apps: Apache Kafka, Apache NiFi, Trino (SQL), JupyterHub, Apache Airflow, Kouncil (Kafka UI).

Dependency Awareness: Ensures prerequisites (e.g., Kafka for Kouncil) are met before installation.

Smart Access: Automatically discovers assigned NodePorts and generates direct clickable links (http://<PublicIP>:<Port>) to access application UIs.

GitOps Dashboard: Manage FluxCD Git Sources and Kustomizations directly. Connect your own Git repositories to drive cluster state.

3. 📊 Monitoring & Observability

One-Click Observability: Automatically installs and patches the Kubernetes Metrics Server for vanilla clusters (insecure TLS support included).

Cluster Capacity: View total aggregated CPU and RAM capacity vs. utilization.

Real-Time Graphs: Visualizes CPU and Memory usage per node with Grafana-style area charts.

Network Stats: Monitors the Master Node's network throughput in real-time.

💻 System Requirements

Master Node (Where this tool runs):

OS: Linux (Debian 11/12/Trixie, Ubuntu 20.04+, Rocky Linux 9, OpenSUSE).

CPU: 2 vCPUs minimum.

RAM: 2 GB RAM minimum.

Permissions: Root/Sudo access is required to install system packages.

Worker Nodes:

CPU: 1 vCPU.

RAM: 1 GB RAM.

📥 Installation & Usage

It is recommended to run this tool inside a Python virtual environment to keep dependencies clean.

1. Update System & Install Python

Ensure Python 3 and pip are installed.

# Debian/Ubuntu
sudo apt update && sudo apt install -y python3-venv python3-pip git

# RHEL/Rocky
sudo dnf install -y python3 git


2. Setup Project & Environment

Clone the repository (or copy the deployer.py file) and set up the environment.

# Create a directory
mkdir k8s-manager
cd k8s-manager

# Create a virtual environment
python3 -m venv venv

# Activate the environment
source venv/bin/activate


3. Install Dependencies

Install the required Python libraries inside the virtual environment.

pip install streamlit kubernetes psutil pyyaml


4. Run the Application

Because the tool needs to install system packages (like kubeadm and containerd) and modify system configurations (disabling swap, loading kernel modules), it must be run with sudo.

# The path to streamlit inside the venv is usually needed when using sudo
sudo ./venv/bin/streamlit run deployer.py --server.address 0.0.0.0 --server.port 8501


Note: The --server.address 0.0.0.0 flag ensures the app is accessible from your browser if you are running this on a remote VM.

5. Access the Dashboard

Open your web browser and navigate to:
http://<YOUR_VM_IP>:8501

🛡️ Security Note

This tool is intended for Day 0 / Day 1 operations (bootstrapping and initial setup) in trusted environments or private networks. It runs with root privileges and exposes a web interface that can control the server. Do not expose this port to the public internet without a VPN or firewall restrictions.
