import streamlit as st
from kubernetes import client, config
import yaml
import time
import subprocess
import socket
import re
import os
import datetime
import psutil # Added for local network metrics
from collections import deque
from kubernetes.client.rest import ApiException

# --- CONSTANTS ---
K8S_ICON_URL = "https://raw.githubusercontent.com/cncf/artwork/master/projects/kubernetes/icon/color/kubernetes-icon-color.png"

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Vanilla K8s Manager",
    page_icon=K8S_ICON_URL,
    layout="wide"
)

# --- STYLING ---
st.markdown("""
    <style>
    /* Import Roboto from Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');

    /* Apply to main app */
    html, body, [class*="css"] {
        font-family: 'Roboto', sans-serif;
    }

    .stButton>button {
        background-color: #326CE5;
        color: white;
        font-weight: bold;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
        margin-bottom: 1rem;
    }
    .terminal-output {
        font-family: 'Courier New', Courier, monospace;
        font-size: 0.8em;
    }
    </style>
""", unsafe_allow_html=True)

# --- HELPER: SHELL EXECUTION ---
def run_shell(command):
    """Runs a shell command and returns output (Blocking)."""
    try:
        result = subprocess.run(
            command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def run_shell_stream(command, placeholder):
    """Runs a shell command and streams output to a Streamlit placeholder."""
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    
    full_output = ""
    display_buffer = deque(maxlen=80)
    
    placeholder.code("🚀 Executing...", language="bash")
    
    try:
        for line in process.stdout:
            full_output += line
            display_buffer.append(line)
            placeholder.code("".join(display_buffer), language="bash")
            
        process.wait()
        return process.returncode == 0, full_output
        
    except Exception as e:
        return False, str(e)

def delete_node(node_name):
    """Deletes a node from the cluster."""
    # Using kubectl delete node removes it from the cluster registry.
    # Note: The kubelet on the worker node will need a reset if rejoining.
    return run_shell(f"kubectl delete node {node_name}")

# --- OS DETECTION LOGIC ---

def detect_os_release():
    """Parses /etc/os-release to detect OS distribution and version."""
    os_info = {"ID": "unknown", "VERSION_ID": "unknown", "PRETTY_NAME": "Unknown Linux", "FAMILY": "unknown"}
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        v = v.strip('"').strip("'")
                        os_info[k] = v
        os_id = os_info.get("ID", "").lower()
        if os_id in ["ubuntu", "debian", "pop", "kali"]: os_info["FAMILY"] = "debian"
        elif os_id in ["rhel", "centos", "rocky", "fedora"]: os_info["FAMILY"] = "rhel"
        elif os_id in ["sles", "opensuse", "opensuse-leap"]: os_info["FAMILY"] = "suse"
    except Exception as e:
        os_info["ERROR"] = str(e)
    return os_info

def get_k8s_install_cmd(os_family):
    if os_family == "debian":
        return """
    sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl gpg
    curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | sudo gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
    sudo apt-get update && sudo apt-get install -y kubelet kubeadm kubectl
    sudo apt-mark hold kubelet kubeadm kubectl
    """
    elif os_family == "rhel":
        return """
    sudo setenforce 0
    sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
    cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.29/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.29/rpm/repodata/repomd.xml.key
exclude=kubelet kubeadm kubectl cri-tools kubernetes-cni
EOF
    sudo dnf install -y kubelet kubeadm kubectl --disableexcludes=kubernetes
    sudo systemctl enable --now kubelet
    """
    elif os_family == "suse":
        return """
    sudo swapoff -a
    sudo zypper addrepo --refresh --check https://pkgs.k8s.io/core:/stable:/v1.29/rpm/ kubernetes
    sudo zypper --gpg-auto-import-keys refresh
    sudo zypper install -y kubelet kubeadm kubectl
    sudo systemctl enable --now kubelet
    """
    return "# Manual Installation Required"

def install_k8s_master(os_info, log_placeholder=None):
    install_cmd = get_k8s_install_cmd(os_info["FAMILY"])
    setup_script = f"""
    sudo swapoff -a
    sudo sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab
    cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
    overlay
    br_netfilter
EOF
    sudo modprobe overlay
    sudo modprobe br_netfilter
    cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
    net.bridge.bridge-nf-call-iptables  = 1
    net.bridge.bridge-nf-call-ip6tables = 1
    net.ipv4.ip_forward                 = 1
EOF
    sudo sysctl --system
    
    # Containerd
    if command -v apt-get &> /dev/null; then
        sudo apt-get update 2>/dev/null || true
        sudo apt-get install -y ca-certificates curl gnupg lsb-release
        sudo install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
        DISTRO_ID=$(. /etc/os-release; echo "$ID")
        DISTRO_CODENAME=$(. /etc/os-release; echo "$VERSION_CODENAME")
        if [ "$DISTRO_CODENAME" = "trixie" ] || [ "$DISTRO_CODENAME" = "sid" ]; then DISTRO_CODENAME="bookworm"; fi
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO_ID $DISTRO_CODENAME stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update && sudo apt-get install -y containerd.io
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y dnf-plugins-core
        sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        sudo dnf install -y containerd.io
    elif command -v zypper &> /dev/null; then
        sudo zypper install -y curl
        sudo zypper addrepo https://download.docker.com/linux/sles/docker-ce.repo
        sudo zypper install -y containerd.io
    fi
    
    sudo mkdir -p /etc/containerd
    containerd config default | sudo tee /etc/containerd/config.toml
    sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
    sudo systemctl restart containerd

    {install_cmd}

    sudo kubeadm init --pod-network-cidr=10.244.0.0/16
    mkdir -p $HOME/.kube
    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    sudo chown $(id -u):$(id -g) $HOME/.kube/config
    kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
    """
    if log_placeholder: return run_shell_stream(setup_script, log_placeholder)
    return run_shell(setup_script)

# --- WORKER SCRIPT GENERATORS ---
def get_join_details():
    success, output = run_shell("sudo kubeadm token create --print-join-command --kubeconfig /etc/kubernetes/admin.conf")
    if not success: return None, output
    
    join_cmd = output.strip()
    match = re.search(r'join\s+([^:\s]+):(\d+)', join_cmd)
    token_match = re.search(r'--token\s+([a-z0-9\.]+)', join_cmd)
    hash_match = re.search(r'--discovery-token-ca-cert-hash\s+sha256:([a-z0-9]+)', join_cmd)
    
    if match and token_match and hash_match:
        return { "master_ip": match.group(1), "token": token_match.group(1), "hash": hash_match.group(1), "full_cmd": join_cmd }, None
    return None, "Regex parsing failed."

def generate_worker_user_data(details, target_os_family):
    install_cmd = get_k8s_install_cmd(target_os_family)
    install_cmd_indented = "\n".join(["    " + line for line in install_cmd.split("\n")])
    join_config = f"""apiVersion: kubeadm.k8s.io/v1beta3
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: {details['master_ip']}:6443
    token: {details['token']}
    caCertHashes:
    - sha256:{details['hash']}
nodeRegistration:
  kubeletExtraArgs:
    node-labels: "installer-ready=true"
"""
    join_config_indented = "\n".join(["      " + line for line in join_config.split("\n")])
    return f"""#cloud-config
package_update: true
write_files:
  - path: /etc/modules-load.d/k8s.conf
    content: |
      overlay
      br_netfilter
  - path: /etc/sysctl.d/k8s.conf
    content: |
      net.bridge.bridge-nf-call-iptables  = 1
      net.bridge.bridge-nf-call-ip6tables = 1
      net.ipv4.ip_forward                 = 1
  - path: /tmp/join-config.yaml
    content: |
{join_config_indented}
runcmd:
  - swapoff -a
  - sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab
  - modprobe overlay
  - modprobe br_netfilter
  - sysctl --system
  - if command -v apt-get &> /dev/null; then apt-get update && apt-get install -y ca-certificates curl gnupg lsb-release; fi
  - mkdir -p /etc/apt/keyrings
  - if [ -f /etc/os-release ]; then . /etc/os-release; fi
  - if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then curl -fsSL https://download.docker.com/linux/$ID/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg; chmod a+r /etc/apt/keyrings/docker.gpg; fi
  - if [ "$VERSION_CODENAME" = "trixie" ] || [ "$VERSION_CODENAME" = "sid" ]; then VERSION_CODENAME="bookworm"; fi
  - if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null; fi
  - if command -v apt-get &> /dev/null; then apt-get update && apt-get install -y containerd.io; fi
  - if command -v dnf &> /dev/null; then dnf install -y dnf-plugins-core && dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo && dnf install -y containerd.io; fi
  - mkdir -p /etc/containerd
  - containerd config default | tee /etc/containerd/config.toml
  - sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
  - systemctl restart containerd
{install_cmd_indented}
  - kubeadm join --config /tmp/join-config.yaml
"""

def generate_worker_bash_script(details, target_os_family):
    install_cmd = get_k8s_install_cmd(target_os_family)
    return f"""#!/bin/bash
set -e
echo "🚀 Starting Worker Node Setup..."
sudo swapoff -a
sudo sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF
sudo modprobe overlay
sudo modprobe br_netfilter
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sudo sysctl --system
if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg lsb-release
    sudo mkdir -p /etc/apt/keyrings
    if [ -f /etc/os-release ]; then . /etc/os-release; fi
    if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then 
        curl -fsSL https://download.docker.com/linux/$ID/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
    fi
    if [ "$VERSION_CODENAME" = "trixie" ] || [ "$VERSION_CODENAME" = "sid" ]; then VERSION_CODENAME="bookworm"; fi
    if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then 
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi
    sudo apt-get update && sudo apt-get install -y containerd.io
elif command -v dnf &> /dev/null; then
    sudo dnf install -y dnf-plugins-core
    sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo dnf install -y containerd.io
fi
sudo mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
sudo systemctl restart containerd
{install_cmd}
cat <<EOF | sudo tee /tmp/join-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: {details['master_ip']}:6443
    token: {details['token']}
    caCertHashes:
    - sha256:{details['hash']}
nodeRegistration:
  kubeletExtraArgs:
    node-labels: "installer-ready=true"
EOF
sudo kubeadm join --config /tmp/join-config.yaml
echo "✅ Worker Setup Complete!"
"""

# --- COMMON HELPER ---
def load_k8s_config(kubeconfig_content=None, context=None):
    try:
        if kubeconfig_content:
            config_dict = yaml.safe_load(kubeconfig_content)
            config.load_kube_config_from_dict(config_dict, context=context)
            return True, "Loaded from pasted config."
        else:
            config.load_kube_config(context=context)
            return True, "Loaded from local ~/.kube/config."
    except Exception as e:
        return False, str(e)

def is_cluster_ready():
    return os.path.exists("/etc/kubernetes/admin.conf")

def get_detailed_nodes():
    try:
        if os.path.exists("/etc/kubernetes/admin.conf"):
            try: config.load_kube_config(config_file="/etc/kubernetes/admin.conf")
            except: pass
        api_core = client.CoreV1Api()
        nodes = api_core.list_node()
        data = []
        for node in nodes.items:
            labels = node.metadata.labels
            role = "Worker"
            if "node-role.kubernetes.io/control-plane" in labels or "node-role.kubernetes.io/master" in labels:
                role = "Master"
            status = "NotReady"
            for c in node.status.conditions:
                if c.type == "Ready" and c.status == "True": status = "Ready"
            ip = "Unknown"
            for addr in node.status.addresses:
                if addr.type == "InternalIP": ip = addr.address
            data.append({
                "Name": node.metadata.name,
                "Role": role,
                "Status": status,
                "Internal IP": ip,
                "CPU": node.status.capacity.get("cpu"),
                "Memory": format_memory(node.status.capacity.get("memory")),
                "OS": node.status.node_info.os_image,
                "Kernel": node.status.node_info.kernel_version,
            })
        return data
    except Exception: return []

def get_cluster_capacity():
    try:
        api_core = client.CoreV1Api()
        nodes = api_core.list_node()
        t_cpu = 0.0
        t_mem = 0.0
        for n in nodes.items:
            t_cpu += parse_cpu_usage(n.status.capacity.get("cpu"))
            t_mem += parse_memory_usage_mib(n.status.capacity.get("memory"))
        return t_cpu, t_mem
    except: return 0.0, 0.0

def get_public_ip_metadata():
    """Attempts to fetch Public IP via Cloud Metadata (AWS IMDSv2)."""
    try:
        # 1. Generate Token (IMDSv2)
        cmd_token = 'curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s --fail'
        token_res = subprocess.run(cmd_token, shell=True, stdout=subprocess.PIPE, text=True, timeout=1)
        if token_res.returncode != 0: return None
        token = token_res.stdout.strip()

        # 2. Fetch IP using Token
        cmd_ip = f'curl -H "X-aws-ec2-metadata-token: {token}" http://169.254.169.254/latest/meta-data/public-ipv4 -s --fail'
        ip_res = subprocess.run(cmd_ip, shell=True, stdout=subprocess.PIPE, text=True, timeout=1)
        if ip_res.returncode == 0:
            return ip_res.stdout.strip()
    except:
        pass
    return None

def get_node_ips():
    """Returns a list of public/accessible IPs for all nodes in the cluster."""
    ips = []
    
    # 1. Try Kubernetes API
    try:
        if os.path.exists("/etc/kubernetes/admin.conf"):
            try: config.load_kube_config(config_file="/etc/kubernetes/admin.conf")
            except: pass
        api = client.CoreV1Api()
        nodes = api.list_node()
        for node in nodes.items:
            # Prefer ExternalIP, fallback to InternalIP
            ext_ip = None
            int_ip = None
            for addr in node.status.addresses:
                if addr.type == "ExternalIP": ext_ip = addr.address
                if addr.type == "InternalIP": int_ip = addr.address
            
            # Use External if available, else Internal
            if ext_ip: ips.append(ext_ip)
            elif int_ip: ips.append(int_ip)
    except Exception: pass

    # 2. Try Cloud Metadata (AWS) if running on Master
    # This fixes the issue where K8s doesn't know the EC2 Public IP
    public_ip = get_public_ip_metadata()
    if public_ip:
        ips.insert(0, public_ip) # Prioritize detected public IP
        
    return list(set(ips))

# --- METRICS & ADDONS FUNCTIONS ---
def install_metrics_server():
    # Use raw string r""" to fix SyntaxWarning with backslashes
    script = r"""
    curl -L https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml -o metrics-server.yaml
    sed -i '/- --metric-resolution=15s/a \        - --kubelet-insecure-tls' metrics-server.yaml
    kubectl apply -f metrics-server.yaml
    """
    return run_shell(script)

def check_metrics_server():
    try:
        res = subprocess.run("kubectl get apiservice v1beta1.metrics.k8s.io", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except: return False

def check_flux_installed():
    try:
        res = subprocess.run("kubectl get crd gitrepositories.source.toolkit.fluxcd.io", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except: return False

def install_flux_cli_and_components():
    script = """
    curl -s https://fluxcd.io/install.sh | sudo bash
    flux check --pre
    flux install
    """
    return run_shell(script)

def get_node_metrics():
    try:
        cust = client.CustomObjectsApi()
        data = cust.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
        metrics = []
        for item in data['items']:
            metrics.append({
                "Name": item['metadata']['name'],
                "CPU (cores)": parse_cpu_usage(item['usage']['cpu']),
                "Memory (MiB)": parse_memory_usage_mib(item['usage']['memory'])
            })
        return metrics
    except: return []

def parse_cpu_usage(cpu_str):
    if not cpu_str: return 0.0
    if cpu_str.endswith('m'): return float(cpu_str[:-1]) / 1000
    if cpu_str.endswith('n'): return float(cpu_str[:-1]) / 1000000000
    return float(cpu_str)

def parse_memory_usage_mib(mem_str):
    if not mem_str: return 0.0
    units = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3}
    match = re.match(r"^([0-9.]+)([a-zA-Z]+)?$", str(mem_str).strip())
    if not match: return 0.0
    val, unit = match.groups()
    mult = units.get(unit, 1)
    return (float(val) * mult) / (1024**2)

def format_memory(mem_str):
    if not mem_str: return "N/A"
    units = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "m": 1e-3, "K": 1000, "M": 1000**2, "G": 1000**3}
    match = re.match(r"^([0-9.]+)([a-zA-Z]+)?$", str(mem_str).strip())
    if not match: return mem_str
    val, unit = match.groups()
    mult = units.get(unit, 1)
    return f"{(float(val) * mult) / (1024**3):.2f} GiB"

# --- GITOPS FUNCTIONS (FLUX) ---
def get_flux_sources():
    """Returns list of GitRepositories."""
    try:
        cmd = "kubectl get gitrepositories -A -o json"
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        if res.returncode != 0: return []
        data = yaml.safe_load(res.stdout)
        sources = []
        for item in data.get('items', []):
            status = "Unknown"
            if 'status' in item and 'conditions' in item['status']:
                for c in item['status']['conditions']:
                    if c['type'] == 'Ready': status = "Ready" if c['status'] == "True" else "Failed"
            sources.append({
                "Name": item['metadata']['name'],
                "Namespace": item['metadata']['namespace'],
                "URL": item['spec']['url'],
                "Status": status
            })
        return sources
    except: return []

def get_flux_kustomizations():
    """Returns list of Kustomizations."""
    try:
        cmd = "kubectl get kustomizations -A -o json"
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        if res.returncode != 0: return []
        data = yaml.safe_load(res.stdout)
        kusts = []
        for item in data.get('items', []):
            status = "Unknown"
            revision = "N/A"
            if 'status' in item:
                revision = item['status'].get('lastAppliedRevision', 'N/A')
                if 'conditions' in item['status']:
                    for c in item['status']['conditions']:
                        if c['type'] == 'Ready': status = "Ready" if c['status'] == "True" else "Failed"
            kusts.append({
                "Name": item['metadata']['name'],
                "Namespace": item['metadata']['namespace'],
                "Path": item['spec']['path'],
                "Source": item['spec']['sourceRef']['name'],
                "Status": status,
                "Revision": revision
            })
        return kusts
    except: return []

def create_flux_source(name, url, branch="main", interval="1m"):
    cmd = f"flux create source git {name} --url={url} --branch={branch} --interval={interval} --export > /tmp/{name}-source.yaml && kubectl apply -f /tmp/{name}-source.yaml"
    return run_shell(cmd)

def create_flux_kustomization(name, source, path, interval="5m"):
    cmd = f"flux create kustomization {name} --source={source} --path={path} --prune=true --interval={interval} --export > /tmp/{name}-kust.yaml && kubectl apply -f /tmp/{name}-kust.yaml"
    return run_shell(cmd)

def reconcile_flux_kustomization(name):
    return run_shell(f"flux reconcile kustomization {name}")

# --- MARKETPLACE CATALOG ---
# REVERTED: Now uses flux-system namespace again to avoid deployment collisions
MARKETPLACE_CATALOG = {
    "kafka": {
        "title": "Apache Kafka",
        "desc": "Distributed event streaming platform.",
        "repo_url": "https://charts.bitnami.com/bitnami",
        "repo_name": "bitnami",
        "chart": "kafka",
        "version": "26.0.0",
        "values": {"zookeeper": {"enabled": True}, "replicaCount": 1},
        "ui_svc": None # Kafka has no default UI
    },
    "kouncil": {
        "title": "Kouncil (Kafka UI)",
        "desc": "Web UI for managing Apache Kafka.",
        "repo_url": "https://consdata.github.io/kouncil/",
        "repo_name": "consdata",
        "chart": "kouncil",
        "version": "1.5.0", 
        "values": {
            "bootstrapServers": "kafka.flux-system.svc.cluster.local:9092",
            "service": {"type": "NodePort"}
        },
        "ui_svc": "kouncil",
        "ui_ns": "flux-system",
        "dependency": "kafka" 
    },
    "nifi": {
        "title": "Apache NiFi",
        "desc": "Data flow automation and processing.",
        "repo_url": "https://cetic.github.io/helm-charts",
        "repo_name": "cetic",
        "chart": "nifi",
        "version": "1.1.0",
        "values": {"persistence": {"enabled": True}, "replicaCount": 1, "service": {"type": "NodePort"}},
        "ui_svc": "nifi",
        "ui_ns": "flux-system" # Reverted to flux-system
    },
    "trino": {
        "title": "Trino (SQL)",
        "desc": "Fast distributed SQL query engine.",
        "repo_url": "https://trinodb.github.io/charts/",
        "repo_name": "trino",
        "chart": "trino",
        "version": "0.18.0",
        "values": {"server": {"workers": 1, "coordinator": True}, "service": {"type": "NodePort"}},
        "ui_svc": "trino",
        "ui_ns": "flux-system" # Reverted to flux-system
    },
    "jupyterhub": {
        "title": "JupyterHub",
        "desc": "Multi-user Notebook server.",
        "repo_url": "https://jupyterhub.github.io/helm-chart/",
        "repo_name": "jupyterhub",
        "chart": "jupyterhub",
        "version": "3.1.0",
        "values": {"proxy": {"service": {"type": "NodePort"}}},
        "ui_svc": "proxy-public",
        "ui_ns": "flux-system" # Reverted to flux-system
    },
    "airflow": {
        "title": "Apache Airflow",
        "desc": "Workflow orchestration platform.",
        "repo_url": "https://airflow.apache.org",
        "repo_name": "apache-airflow",
        "chart": "airflow",
        "version": "1.11.0",
        "values": {"executor": "KubernetesExecutor", "webserver": {"service": {"type": "NodePort"}}},
        "ui_svc": "airflow-webserver",
        "ui_ns": "flux-system" # Reverted to flux-system
    }
}

def check_app_installed(name):
    """Checks if a HelmRelease exists for the app."""
    try:
        res = subprocess.run(f"kubectl get helmrelease -n flux-system {name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except: return False

def get_service_nodeport(namespace, service_name):
    """Retrieves NodePort for a service."""
    try:
        cmd = f"kubectl get svc -n {namespace} {service_name} -o jsonpath='{{.spec.ports[0].nodePort}}'"
        # Silence stderr to avoid "NotFound" spam in UI if service is provisioning
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if res.returncode == 0:
            port = res.stdout.strip()
            if port and port.isdigit(): return port
        return None
    except: return None

def install_marketplace_app(key, config):
    """Generates Flux YAML and applies it."""
    # 1. HelmRepository
    repo_yaml = f"""apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: {config['repo_name']}
  namespace: flux-system
spec:
  interval: 1h
  url: {config['repo_url']}
"""
    # 2. HelmRelease
    values_yaml = yaml.dump(config['values'])
    values_indented = "\n".join(["    " + line for line in values_yaml.split("\n")])
    
    # Removed targetNamespace: default to revert behavior
    release_yaml = f"""apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: {key}
  namespace: flux-system
spec:
  interval: 5m
  chart:
    spec:
      chart: {config['chart']}
      version: "{config['version']}"
      sourceRef:
        kind: HelmRepository
        name: {config['repo_name']}
        namespace: flux-system
      interval: 1m
  values:
{values_indented}
"""
    
    with open(f"/tmp/{key}-install.yaml", "w") as f:
        f.write(repo_yaml + "\n---\n" + release_yaml)
        
    return run_shell(f"kubectl apply -f /tmp/{key}-install.yaml")

def uninstall_marketplace_app(key):
    return run_shell(f"kubectl delete helmrelease -n flux-system {key} --ignore-not-found=true --wait=false")

def is_cluster_unhealthy(nodes_data):
    """Checks for unhealthy nodes."""
    not_ready = [n['Name'] for n in nodes_data if n['Status'] != 'Ready']
    if not_ready:
        return True, f"Nodes NotReady: {', '.join(not_ready)}"
    return False, ""

# --- MAIN UI ---

col_logo, col_title = st.columns([1, 12])
with col_logo:
    st.image(K8S_ICON_URL, width=70)
with col_title:
    st.title("Vanilla K8s Manager & Deployer")

tabs = st.tabs(["1. Cluster Management", "2. Marketplace", "3. Add-ons & GitOps", "4. Info"])

# --- TAB 1: CLUSTER MANAGEMENT ---
with tabs[0]:
    st.header("Cluster Bootstrap")
    
    # OS Detection Display
    os_info = detect_os_release()
    st.info(f"**System Info:** {os_info['PRETTY_NAME']} (Family: {os_info['FAMILY']})")
    
    # Check status
    ready = is_cluster_ready()
    
    if ready:
        st.success("✅ **Kubernetes Master is running on this node.**")
        
        st.subheader("Cluster Nodes (Live Status)")
        
        c1, c2 = st.columns([3, 1])
        with c1:
            st.caption("Manage nodes in the cluster.")
        with c2:
            if st.button("🔄 Refresh"): st.rerun()
            
        nodes_data = get_detailed_nodes()
        if nodes_data:
            # DataTables-style view
            st.dataframe(nodes_data, width='stretch')
            
            # Detach functionality
            workers = [n['Name'] for n in nodes_data if n['Role'] == 'Worker']
            if workers:
                with st.expander("❌ Detach Worker Node"):
                    c1, c2 = st.columns([3, 1])
                    with c1:
                        node_to_del = st.selectbox("Select Worker", options=workers)
                    with c2:
                        st.write("") # spacer
                        st.write("") 
                        if st.button("Detach Node"):
                            delete_node(node_to_del)
                            st.rerun()
        else:
             st.info("No nodes detected...")

        st.markdown("---")
        
        st.subheader("Add Worker Nodes")
        st.write("Generate configuration to add new VMs to this cluster.")
        
        worker_os_family = st.radio(
            "Select Worker OS Family:",
            ["debian", "rhel", "suse"],
            format_func=lambda x: x.upper() + " (Ubuntu, Debian)" if x == "debian" else (x.upper() + " (Rocky, CentOS, Fedora)" if x == "rhel" else "SUSE (SLES, OpenSUSE)"),
            horizontal=True,
            index=0 if os_info['FAMILY'] == 'debian' else (1 if os_info['FAMILY'] == 'rhel' else 2)
        )
        
        if st.button("Generate Worker Configuration"):
            details, error_msg = get_join_details()
            if details:
                user_data = generate_worker_user_data(details, worker_os_family)
                bash_script = generate_worker_bash_script(details, worker_os_family)
                
                st.code(details['full_cmd'], language="bash")
                st.caption("Manual Join Command")
                
                c1, c2 = st.columns(2)
                
                with c1:
                    st.download_button("⬇️ Download user-data.yaml", user_data, "worker-user-data.yaml", "text/yaml")
                with c2:
                    st.download_button("⬇️ Download worker-setup.sh", bash_script, "worker-setup.sh", "text/x-sh")
            else:
                st.error("Could not generate token. Ensure you are running as sudo/root.")
                if error_msg: st.code(error_msg, language="bash")
    else:
        st.warning(f"❌ Kubernetes Cluster is NOT initialized on this machine ({os_info['PRETTY_NAME']}).")
        
        if os_info['FAMILY'] == 'unknown':
            st.error("⚠️ Unknown OS family. Automatic installation might fail.")
            
        if st.button("🛠️ Install Master Node & Initialize Cluster"):
            terminal_placeholder = st.empty()
            with st.spinner("Installing K8s components... (Logs below)"):
                success, logs = install_k8s_master(os_info, terminal_placeholder)
                
                if success:
                    st.success("Cluster Initialized Successfully!")
                    st.balloons()
                    time.sleep(2)
                    st.rerun()
                else:
                    st.error("Installation Failed")

# --- TAB 2: MARKETPLACE ---
with tabs[1]:
    st.header("🛍️ App Marketplace")
    st.caption("One-click installation for Data & Analytics tools using FluxCD GitOps Controllers.")
    
    # Check Health
    nodes = get_detailed_nodes()
    unhealthy, reason = is_cluster_unhealthy(nodes)
    
    if unhealthy:
        st.error(f"⛔ **Cluster Unhealthy**: {reason}")
        st.warning("Installations are disabled until nodes are Ready to prevent overload.")
    
    if not check_flux_installed():
        st.warning("⚠️ FluxCD is required for the Marketplace.")
        st.info("Go to the **Add-ons & GitOps** tab to install Flux first.")
    else:
        col1, col2 = st.columns(2)
        apps = list(MARKETPLACE_CATALOG.items())
        
        def render_card(col, key, cfg):
            with col:
                with st.container(border=True):
                    st.subheader(cfg['title'])
                    st.write(cfg['desc'])
                    
                    # Check dependency if exists
                    dep_met = True
                    if 'dependency' in cfg:
                         if not check_app_installed(cfg['dependency']):
                             dep_met = False
                             st.warning(f"⚠️ Requires '{MARKETPLACE_CATALOG[cfg['dependency']]['title']}' to be installed first.")
                    
                    is_installed = check_app_installed(key)
                    
                    if is_installed:
                        st.success("✅ Installed")
                        
                        # --- Access & Manage Section ---
                        if cfg['ui_svc']:
                            with st.expander("🔌 Access & Manage"):
                                node_port = get_service_nodeport(cfg.get('ui_ns', 'flux-system'), cfg['ui_svc'])
                                if node_port:
                                    st.markdown("**Direct Access Points:**")
                                    node_ips = get_node_ips()
                                    if node_ips:
                                        for ip in node_ips:
                                            url = f"http://{ip}:{node_port}"
                                            st.markdown(f"👉 [{url}]({url})")
                                    else:
                                        st.warning("Could not detect Node IPs.")
                                else:
                                    st.warning("⏳ Waiting for NodePort... (Click Refresh)")
                                    if st.button("Refresh Port", key=f"ref_{key}"): st.rerun()
                        
                        if st.button(f"🗑️ Uninstall {cfg['title']}", key=f"uninst_{key}"):
                            success, log = uninstall_marketplace_app(key)
                            if success: st.rerun()
                            else: st.error(log)
                    else:
                        # Disable install if unhealthy or dependency missing
                        btn_disabled = unhealthy or not dep_met
                        btn = st.button(f"🚀 Install {cfg['title']}", key=f"inst_{key}", disabled=btn_disabled)
                        if btn:
                            with st.spinner("Applying Flux Manifests..."):
                                success, log = install_marketplace_app(key, cfg)
                                if success: 
                                    st.success("Installation Triggered!")
                                    st.info("Flux is now pulling the charts. Check 'Add-ons & GitOps' for status.")
                                    time.sleep(2)
                                    st.rerun()
                                else: st.error(log)

        for i, (key, cfg) in enumerate(apps):
            if i % 2 == 0: render_card(col1, key, cfg)
            else: render_card(col2, key, cfg)

# --- TAB 3: ADD-ONS & GITOPS ---
with tabs[2]:
    st.header("📊 Cluster Add-ons & GitOps")
    
    st.subheader("1. Observability (Metrics Server)")
    has_metrics = check_metrics_server()
    if not has_metrics:
        if st.button("🛠️ Install Metrics Server"):
            with st.spinner("Installing..."):
                success, log = install_metrics_server()
                if success: st.success("Installed!"); st.rerun()
                else: st.error(log)
    else:
        st.success("✅ Metrics Server is Active")
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("▶️ Start Live Monitor"): st.session_state['monitoring'] = True
        with col2:
            if st.button("⏹️ Stop"): st.session_state['monitoring'] = False
        
        m1, m2, m3 = st.columns(3)
        cpu_metric = m1.empty()
        mem_metric = m2.empty()
        net_metric = m3.empty()

        st.markdown("#### 📉 CPU Utilization (Cores)")
        cpu_chart = st.empty()
        
        st.markdown("#### 💾 RAM Utilization (MiB)")
        mem_chart = st.empty()
        
        st.markdown("#### 🌐 Network I/O (Master Node)")
        net_chart = st.empty()
        
        if st.session_state.get('monitoring', False):
            if 'cpu_history' not in st.session_state: st.session_state['cpu_history'] = []
            if 'mem_history' not in st.session_state: st.session_state['mem_history'] = []
            if 'net_history' not in st.session_state: st.session_state['net_history'] = []
            
            tot_cpu, tot_mem = get_cluster_capacity()

            for _ in range(30): 
                if not st.session_state.get('monitoring'): break
                metrics = get_node_metrics()
                now = datetime.datetime.now().strftime("%H:%M:%S")
                cpu_row = {"Time": now}; mem_row = {"Time": now}
                curr_cpu = 0.0
                curr_mem = 0.0

                for m in metrics:
                    cpu_row[m['Name']] = m['CPU (cores)']
                    mem_row[m['Name']] = m['Memory (MiB)']
                    curr_cpu += m['CPU (cores)']
                    curr_mem += m['Memory (MiB)']
                
                cpu_metric.metric("Cluster CPU", f"{curr_cpu:.2f} / {tot_cpu:.2f} Cores", f"{(curr_cpu/tot_cpu)*100:.1f}%" if tot_cpu else None)
                mem_metric.metric("Cluster RAM", f"{curr_mem:.0f} / {tot_mem:.0f} MiB", f"{(curr_mem/tot_mem)*100:.1f}%" if tot_mem else None)
                
                st.session_state['cpu_history'].append(cpu_row)
                st.session_state['mem_history'].append(mem_row)
                if len(st.session_state['cpu_history']) > 50:
                    st.session_state['cpu_history'].pop(0); st.session_state['mem_history'].pop(0)
                
                cpu_chart.area_chart(st.session_state['cpu_history'], x="Time", y=[k for k in cpu_row.keys() if k != "Time"])
                mem_chart.area_chart(st.session_state['mem_history'], x="Time", y=[k for k in mem_row.keys() if k != "Time"])
                
                net = psutil.net_io_counters()
                sent = net.bytes_sent/1024/1024
                recv = net.bytes_recv/1024/1024
                
                net_metric.metric("Network (Master)", f"⬆️{sent:.1f} ⬇️{recv:.1f} MB", help="Cumulative traffic since boot")

                net_row = { "Time": now, "Sent (MB)": sent, "Recv (MB)": recv }
                st.session_state['net_history'].append(net_row)
                if len(st.session_state['net_history']) > 50: st.session_state['net_history'].pop(0)
                net_chart.line_chart(st.session_state['net_history'], x="Time")
                
                time.sleep(2)
            if st.session_state.get('monitoring'): st.rerun()

    st.markdown("---")
    st.subheader("2. GitOps (FluxCD)")
    
    has_flux = check_flux_installed()
    
    if not has_flux:
        if st.button("🛠️ Install FluxCD (CLI + Controllers)"):
            with st.spinner("Installing Flux..."):
                success, log = install_flux_cli_and_components()
                if success: st.success("Flux Installed!"); st.balloons()
                else: st.error(log)
    else:
        st.success("✅ FluxCD is Installed & Active")
        
        # --- GITOPS MANAGER UI (Moved Here) ---
        # 1. Source Management
        st.subheader("🔗 Git Sources (Repositories)")
        sources = get_flux_sources()
        if sources:
            st.dataframe(sources, width='stretch')
        else:
            st.info("No Git Repositories connected.")
            
        with st.expander("➕ Connect New Git Repository"):
            with st.form("add_source"):
                src_name = st.text_input("Name (e.g., 'podinfo')", help="Lowercase, no spaces")
                src_url = st.text_input("Git URL (HTTPS)", help="https://github.com/stefanprodan/podinfo")
                src_branch = st.text_input("Branch", value="main")
                if st.form_submit_button("Connect Repository"):
                    if src_name and src_url:
                        success, log = create_flux_source(src_name, src_url, src_branch)
                        if success: st.success("Repository Connected!"); time.sleep(1); st.rerun()
                        else: st.error(f"Failed: {log}")
                    else: st.error("Name and URL required.")

        st.markdown("---")

        # 2. Application Management
        st.subheader("📦 Applications (Kustomizations)")
        kusts = get_flux_kustomizations()
        
        if kusts:
            for k in kusts:
                status_color = "🟢" if k['Status'] == "Ready" else "🔴"
                with st.expander(f"{status_color} {k['Name']} (Rev: {k['Revision'][:7]})"):
                    c1, c2, c3 = st.columns([2, 2, 1])
                    with c1:
                        st.write(f"**Source:** {k['Source']}")
                        st.write(f"**Path:** `{k['Path']}`")
                    with c2:
                        st.write(f"**Status:** {k['Status']}")
                        st.write(f"**Full Revision:** {k['Revision']}")
                    with c3:
                        if st.button("🔄 Sync Now", key=f"sync_{k['Name']}"):
                            reconcile_flux_kustomization(k['Name'])
                            st.success("Sync Triggered")
                            time.sleep(1)
                            st.rerun()
        else:
            st.info("No Applications configured.")

        with st.expander("➕ Create New Application Deployment"):
            with st.form("add_kust"):
                k_name = st.text_input("App Name", help="Lowercase")
                src_options = [s['Name'] for s in sources] if sources else []
                k_source = st.selectbox("Select Git Source", src_options) if src_options else st.text_input("Git Source Name")
                k_path = st.text_input("Path in Repo", value="./", help="e.g., ./kustomize")
                
                if st.form_submit_button("Deploy Application"):
                    if k_name and k_source:
                        success, log = create_flux_kustomization(k_name, k_source, k_path)
                        if success: st.success("Application Created!"); time.sleep(1); st.rerun()
                        else: st.error(f"Failed: {log}")
                    else: st.error("Fill all fields.")

# --- TAB 5: INFO ---
with tabs[3]:
    st.header("ℹ️ Cluster Information")
    hw_col1, hw_col2 = st.columns(2)
    with hw_col1: st.info("**Master Node**\n\n- 2 CPUs\n- 2 GB RAM\n- Swap Disabled")
    with hw_col2: st.info("**Worker Node**\n\n- 1 CPU\n- 1 GB RAM\n- Swap Disabled")
    st.markdown("---")
    st.info("**Debian** (11/12/Trixie), **Ubuntu** (20.04/22.04/24.04), **RHEL/CentOS** (8/9), **SUSE** (Leap/Tumbleweed)")