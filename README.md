# kubernetes-cluster-deployer
☸️ Vanilla K8s Manager & Deployer

Vanilla K8s Manager is a lightweight, single-file web tool designed to bootstrap, manage, and monitor "Vanilla" Kubernetes clusters on bare-metal servers or VMs.

Built with Python and Streamlit, it simplifies the complex process of setting up kubeadm clusters into a few clicks, offering a unified interface for cluster creation, worker node joining, application deployment, and real-time monitoring.

<img width="836" height="1148" alt="image" src="https://github.com/user-attachments/assets/80b857b6-bf8e-4e6a-8a3e-63f6f5eb737d" />

✨ Key Features

1. 🛠️ Cluster Bootstrap & Management

Automated Master Setup: One-click installation of Kubernetes Control Plane components (kubeadm, kubelet, kubectl, containerd, flannel CNI) on a fresh Linux VM.

Smart OS Detection: Automatically detects and adapts to Debian/Ubuntu (apt), RHEL/Rocky/CentOS (dnf), and SUSE (zypper).

Worker Node Onboarding: Generates ready-to-use Cloud-Init (user-data.yaml) and Bash (worker-setup.sh) scripts to join worker nodes to the cluster easily.

Live Node Status: View real-time status of all nodes in the cluster, including hardware specs (CPU/RAM) and kernel versions.

2. 🚀 Application Deployment

Streamlined Deployer: Deploy containerized applications (Deployment + Service) in seconds.

Infrastructure Targeting: Use Node Affinity to pin specific workloads to specific VMs/Nodes via a visual multi-select interface.

Workload Dashboard: View running deployments, replica counts, and image versions.

Lifecycle Management: Delete applications and services directly from the UI.

3. 📊 Monitoring & Observability

One-Click Metrics: Automatically installs and patches the Kubernetes Metrics Server for vanilla clusters.

Real-Time Graphs: Visualizes CPU and Memory usage per node with Grafana-style area charts.

Network Stats: Monitors the Master Node's network throughput in real-time.

Live Terminal: Watch installation logs stream in real-time within the browser.

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
