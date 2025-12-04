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

# --- OS DETECTION LOGIC ---

def detect_os_release():
    """Parses /etc/os-release to detect OS distribution and version."""
    os_info = {
        "ID": "unknown",
        "VERSION_ID": "unknown",
        "PRETTY_NAME": "Unknown Linux",
        "FAMILY": "unknown"
    }
    
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        # Remove quotes
                        v = v.strip('"').strip("'")
                        os_info[k] = v
        
        # Determine Family for package management
        os_id = os_info.get("ID", "").lower()
        if os_id in ["ubuntu", "debian", "pop", "kali"]:
            os_info["FAMILY"] = "debian"
        elif os_id in ["rhel", "centos", "rocky", "fedora", "almalinux"]:
            os_info["FAMILY"] = "rhel"
        elif os_id in ["sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed"]:
            os_info["FAMILY"] = "suse"
            
    except Exception as e:
        os_info["ERROR"] = str(e)
        
    return os_info

def get_k8s_install_cmd(os_family):
    """Returns the bash commands to install kubeadm/kubectl based on OS."""
    
    if os_family == "debian":
        return """
    # Debian/Ubuntu
    sudo apt-get update
    sudo apt-get install -y apt-transport-https ca-certificates curl gpg
    
    # K8s Repo (v1.29)
    # Added --yes to gpg to overwrite existing keyrings without prompt
    curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | sudo gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
    
    sudo apt-get update
    sudo apt-get install -y kubelet kubeadm kubectl
    sudo apt-mark hold kubelet kubeadm kubectl
    """
    
    elif os_family == "rhel":
        return """
    # RHEL/Rocky/CentOS
    
    # Set SELinux to permissive mode (effectively disabled)
    sudo setenforce 0
    sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

    # K8s Repo (v1.29)
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
    # SuSE/OpenSUSE
    
    # Disable Swap (Critical for K8s)
    sudo swapoff -a
    
    # K8s Repo (v1.29)
    sudo zypper addrepo --refresh --check https://pkgs.k8s.io/core:/stable:/v1.29/rpm/ kubernetes
    sudo zypper --gpg-auto-import-keys refresh
    sudo zypper install -y kubelet kubeadm kubectl
    sudo systemctl enable --now kubelet
    """
    
    else:
        return "# UNSUPPORTED OS FAMILY: Manual Installation Required"

# --- BOOTSTRAP LOGIC (SERVER SIDE) ---

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
    # Use Popen to grab stdout as it happens
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    
    full_output = ""
    # Use a deque to keep only the last 80 lines for the display buffer
    display_buffer = deque(maxlen=80)
    
    # Header
    placeholder.code("🚀 Starting installation...", language="bash")
    
    try:
        for line in process.stdout:
            full_output += line
            display_buffer.append(line)
            
            # Update the UI with only the last 80 lines (mimics a sliding terminal window)
            placeholder.code("".join(display_buffer), language="bash")
            
        process.wait()
        return process.returncode == 0, full_output
        
    except Exception as e:
        return False, str(e)

def is_cluster_ready():
    """Checks if the cluster is actually initialized (admin.conf exists)."""
    # Simply checking 'which kubeadm' is not enough; we need the config file.
    return os.path.exists("/etc/kubernetes/admin.conf")

def format_memory(mem_str):
    """Parses K8s memory string (e.g., 2048Ki) and formats to GiB."""
    if not mem_str: return "N/A"
    
    # Units in bytes
    units = {
        "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4, "Pi": 1024**5, "Ei": 1024**6,
        "m": 1e-3,  "K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4, "P": 1000**5, "E": 1000**6
    }
    
    # Simple regex to separate value from unit
    # Matches: 1234, 1234Ki, 1234.5Mi
    match = re.match(r"^([0-9.]+)([a-zA-Z]+)?$", str(mem_str).strip())
    if not match:
        return mem_str # Return original if parse fails
        
    value, unit = match.groups()
    value = float(value)
    
    multiplier = units.get(unit, 1) # Default to bytes (multiplier 1) if no unit found
    bytes_val = value * multiplier
    
    gib_val = bytes_val / (1024**3)
    return f"{gib_val:.2f} GiB"

def parse_cpu_usage(cpu_str):
    """Parses cpu string (100m, 1, 1500m) to float cores."""
    if not cpu_str: return 0.0
    if cpu_str.endswith('m'):
        return float(cpu_str[:-1]) / 1000
    if cpu_str.endswith('n'): # nano cores
        return float(cpu_str[:-1]) / 1000000000
    return float(cpu_str)

def parse_memory_usage_mib(mem_str):
    """Parses memory string to MiB float."""
    if not mem_str: return 0.0
    # Simplified parser reusing logic from format_memory but returning MiB
    units = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3}
    match = re.match(r"^([0-9.]+)([a-zA-Z]+)?$", str(mem_str).strip())
    if not match: return 0.0
    val, unit = match.groups()
    mult = units.get(unit, 1)
    bytes_val = float(val) * mult
    return bytes_val / (1024**2)

def get_detailed_nodes():
    """Fetches detailed node info for the data table."""
    try:
        # Auto-load config if running on master
        if os.path.exists("/etc/kubernetes/admin.conf"):
            try:
                config.load_kube_config(config_file="/etc/kubernetes/admin.conf")
            except:
                pass # Already loaded or issue

        api_core = client.CoreV1Api()
        nodes = api_core.list_node()
        data = []
        for node in nodes.items:
            # Role
            labels = node.metadata.labels
            role = "Worker"
            if "node-role.kubernetes.io/control-plane" in labels or "node-role.kubernetes.io/master" in labels:
                role = "Master"
            
            # Status
            status = "NotReady"
            for c in node.status.conditions:
                if c.type == "Ready" and c.status == "True":
                    status = "Ready"
            
            # IP
            ip = "Unknown"
            for addr in node.status.addresses:
                if addr.type == "InternalIP":
                    ip = addr.address
            
            # Memory Formatting
            raw_mem = node.status.capacity.get("memory")
            fmt_mem = format_memory(raw_mem)

            data.append({
                "Name": node.metadata.name,
                "Role": role,
                "Status": status,
                "Internal IP": ip,
                "CPU": node.status.capacity.get("cpu"),
                "Memory": fmt_mem,
                "OS Image": node.status.node_info.os_image,
                "Kernel": node.status.node_info.kernel_version,
                "Runtime": node.status.node_info.container_runtime_version,
            })
        return data
    except Exception:
        return []

def install_k8s_master(os_info, log_placeholder=None):
    """Installs Containerd, Kubeadm and initializes the cluster."""
    
    install_cmd = get_k8s_install_cmd(os_info["FAMILY"])
    
    setup_script = f"""
    # 0. Disable Swap (Universal Requirement)
    sudo swapoff -a
    sudo sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab

    # 1. Sysctl
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

    # 2. Containerd (Robust Manual Install with Trixie Fallback)
    if command -v apt-get &> /dev/null; then
        sudo apt-get update 2>/dev/null || true
        sudo apt-get install -y ca-certificates curl gnupg lsb-release
        
        # Add Docker GPG Key
        sudo install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg

        # Detect Codename and Fallback for Trixie
        DISTRO_ID=$(. /etc/os-release; echo "$ID")
        DISTRO_CODENAME=$(. /etc/os-release; echo "$VERSION_CODENAME")
        
        # Force Bookworm if Trixie or Sid
        if [ "$DISTRO_CODENAME" = "trixie" ] || [ "$DISTRO_CODENAME" = "sid" ]; then
            echo "Detected Debian Trixie/Sid. Falling back to Bookworm for Docker repo."
            DISTRO_CODENAME="bookworm"
        fi
        
        # Add Repo
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO_ID \
          $DISTRO_CODENAME stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
          
        sudo apt-get update
        sudo apt-get install -y containerd.io
        
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y dnf-plugins-core
        sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        sudo dnf install -y containerd.io
    elif command -v zypper &> /dev/null; then
        sudo zypper install -y curl
        sudo zypper addrepo https://download.docker.com/linux/sles/docker-ce.repo
        sudo zypper install -y containerd.io
    fi
    
    # Configure containerd
    sudo mkdir -p /etc/containerd
    containerd config default | sudo tee /etc/containerd/config.toml
    # Enable SystemdCgroup
    sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
    sudo systemctl restart containerd

    # 3. Kubeadm (OS Specific)
    {install_cmd}

    # 4. Init Cluster
    # We use a specific CIDR for Flannel
    sudo kubeadm init --pod-network-cidr=10.244.0.0/16
    
    # 5. Kubeconfig for Root (and user)
    mkdir -p $HOME/.kube
    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    sudo chown $(id -u):$(id -g) $HOME/.kube/config
    
    # 6. Install Network Plugin (Flannel)
    kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
    """
    
    if log_placeholder:
        return run_shell_stream(setup_script, log_placeholder)
    else:
        return run_shell(setup_script)

def get_join_details():
    """Generates a fresh token and retrieves the discovery hash and API server IP."""
    # Use explicit --kubeconfig to avoid path issues when running as sudo/root vs user
    success, output = run_shell("sudo kubeadm token create --print-join-command --kubeconfig /etc/kubernetes/admin.conf")
    if not success:
        return None, output  # Return error output
    
    join_cmd = output.strip()
    
    # Updated regex to capture IP and Port separately to avoid duplication in template
    match = re.search(r'join\s+([^:\s]+):(\d+)', join_cmd)
    token_match = re.search(r'--token\s+([a-z0-9\.]+)', join_cmd)
    hash_match = re.search(r'--discovery-token-ca-cert-hash\s+sha256:([a-z0-9]+)', join_cmd)
    
    if match and token_match and hash_match:
        return {
            "master_ip": match.group(1), # Just the IP
            "token": token_match.group(1),
            "hash": hash_match.group(1),
            "full_cmd": join_cmd
        }, None
    return None, "Regex parsing failed on join command."

def generate_worker_user_data(details, target_os_family):
    """Injects dynamic tokens into the user-data template (Cloud-Init)."""
    
    install_cmd = get_k8s_install_cmd(target_os_family)
    
    # Indent the install command for YAML compatibility
    install_cmd_indented = "\n".join(["    " + line for line in install_cmd.split("\n")])

    # Kubeadm Config for Node Labels
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
    # Indent config for write_files
    join_config_indented = "\n".join(["      " + line for line in join_config.split("\n")])

    template = f"""#cloud-config
package_update: true
package_upgrade: true

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
  # 1. Disable Swap
  - swapoff -a
  - sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab

  # 2. Load Modules & Sysctl
  - modprobe overlay
  - modprobe br_netfilter
  - sysctl --system

  # 3. Install Container Runtime (Containerd)
  - if command -v apt-get &> /dev/null; then apt-get update && apt-get install -y ca-certificates curl gnupg lsb-release; fi
  - mkdir -p /etc/apt/keyrings
  - if [ -f /etc/os-release ]; then . /etc/os-release; fi
  - if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then curl -fsSL https://download.docker.com/linux/$ID/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg; chmod a+r /etc/apt/keyrings/docker.gpg; fi
  - if [ "$VERSION_CODENAME" = "trixie" ] || [ "$VERSION_CODENAME" = "sid" ]; then VERSION_CODENAME="bookworm"; fi
  - if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null; fi
  - if command -v apt-get &> /dev/null; then apt-get update && apt-get install -y containerd.io; fi
  - if command -v dnf &> /dev/null; then dnf install -y dnf-plugins-core && dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo && dnf install -y containerd.io; fi

  # Configure Containerd
  - mkdir -p /etc/containerd
  - containerd config default | tee /etc/containerd/config.toml
  - sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
  - systemctl restart containerd

  # 4. Install Kubernetes Tools
{install_cmd_indented}

  # 5. JOIN THE CLUSTER (Using Config for Labels)
  - kubeadm join --config /tmp/join-config.yaml
"""
    return template

def generate_worker_bash_script(details, target_os_family):
    """Generates a bash script for worker node setup."""
    
    install_cmd = get_k8s_install_cmd(target_os_family)
    
    script = f"""#!/bin/bash
set -e

echo "🚀 Starting Worker Node Setup..."

# 0. Disable Swap
echo "Disabling Swap..."
sudo swapoff -a
sudo sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab

# 1. Load Modules & Sysctl
echo "Configuring Sysctl..."
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

# 2. Install Container Runtime (Containerd)
echo "Installing Containerd..."

if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg lsb-release
    sudo mkdir -p /etc/apt/keyrings
    if [ -f /etc/os-release ]; then . /etc/os-release; fi
    
    # Add Docker Key
    if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then 
        curl -fsSL https://download.docker.com/linux/$ID/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
    fi
    
    # Fallback for Trixie
    if [ "$VERSION_CODENAME" = "trixie" ] || [ "$VERSION_CODENAME" = "sid" ]; then 
        VERSION_CODENAME="bookworm"
        echo "Detected Trixie/Sid, falling back to Bookworm for Docker."
    fi
    
    # Add Repo
    if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then 
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi
    
    sudo apt-get update && sudo apt-get install -y containerd.io

elif command -v dnf &> /dev/null; then
    sudo dnf install -y dnf-plugins-core
    sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo dnf install -y containerd.io
fi

# Configure Containerd
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
sudo systemctl restart containerd

# 3. Install Kubernetes Tools
echo "Installing Kubeadm/Kubelet..."
{install_cmd}

# 4. Create Join Config
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

# 5. Join Cluster
echo "Joining Cluster..."
sudo kubeadm join --config /tmp/join-config.yaml

echo "✅ Worker Setup Complete!"
"""
    return script

# --- EXISTING CLIENT LOGIC ---

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

def get_cluster_nodes():
    try:
        api_core = client.CoreV1Api()
        nodes = api_core.list_node()
        return [node.metadata.name for node in nodes.items]
    except Exception:
        return []

def get_active_workloads(namespace="default"):
    """Fetches list of active Deployments in the namespace."""
    try:
        api_apps = client.AppsV1Api()
        deps = api_apps.list_namespaced_deployment(namespace)
        workloads = []
        for dep in deps.items:
            workloads.append({
                "Name": dep.metadata.name,
                "Ready": f"{dep.status.ready_replicas or 0}/{dep.spec.replicas}",
                "Image": dep.spec.template.spec.containers[0].image,
                "Age": (datetime.datetime.now(datetime.timezone.utc) - dep.metadata.creation_timestamp).days
            })
        return workloads
    except Exception:
        return []

def delete_app(app_name, namespace="default"):
    """Deletes Deployment and associated Service."""
    logs = []
    api_apps = client.AppsV1Api()
    api_core = client.CoreV1Api()
    
    try:
        api_apps.delete_namespaced_deployment(app_name, namespace)
        logs.append(f"✅ Deleted Deployment: {app_name}")
    except Exception as e:
        logs.append(f"⚠️ Deployment delete failed: {e}")
        
    try:
        api_core.delete_namespaced_service(app_name, namespace)
        logs.append(f"✅ Deleted Service: {app_name}")
    except Exception as e:
        pass # Service might not exist
        
    return logs

def deploy_resources(app_name, image, port, replicas, service_type, namespace, target_nodes):
    api_apps = client.AppsV1Api()
    api_core = client.CoreV1Api()
    logs = []
    
    labels = {"app": app_name}
    affinity = None
    if target_nodes:
        affinity = client.V1Affinity(
            node_affinity=client.V1NodeAffinity(
                required_during_scheduling_ignored_during_execution=client.V1NodeSelector(
                    node_selector_terms=[
                        client.V1NodeSelectorTerm(
                            match_expressions=[
                                client.V1NodeSelectorRequirement(
                                    key="kubernetes.io/hostname",
                                    operator="In",
                                    values=target_nodes
                                )
                            ]
                        )
                    ]
                )
            )
        )
    
    container = client.V1Container(name=app_name, image=image, ports=[client.V1ContainerPort(container_port=port)])
    template = client.V1PodTemplateSpec(metadata=client.V1ObjectMeta(labels=labels), spec=client.V1PodSpec(containers=[container], affinity=affinity))
    spec = client.V1DeploymentSpec(replicas=replicas, template=template, selector={"matchLabels": labels})
    deployment = client.V1Deployment(api_version="apps/v1", kind="Deployment", metadata=client.V1ObjectMeta(name=app_name, labels=labels), spec=spec)
    
    try:
        api_apps.create_namespaced_deployment(namespace=namespace, body=deployment)
        logs.append(f"✅ Deployment '{app_name}' created.")
    except ApiException as e:
        if e.status == 409: logs.append(f"⚠️ Deployment '{app_name}' already exists.")
        else: raise e

    svc_spec = client.V1ServiceSpec(selector=labels, ports=[client.V1ServicePort(port=port, target_port=port)], type=service_type)
    service = client.V1Service(api_version="v1", kind="Service", metadata=client.V1ObjectMeta(name=app_name, labels=labels), spec=svc_spec)
    
    try:
        api_core.create_namespaced_service(namespace=namespace, body=service)
        logs.append(f"✅ Service '{app_name}' created.")
    except ApiException as e:
        if e.status == 409: logs.append(f"⚠️ Service '{app_name}' already exists.")
        else: raise e
            
    return logs

# --- METRICS FUNCTIONS ---

def install_metrics_server():
    """Installs Metrics Server with insecure TLS patch for vanilla k8s."""
    # 1. Download official manifest
    # 2. Patch Deployment to add --kubelet-insecure-tls
    script = """
    echo "⬇️ Downloading Metrics Server..."
    curl -L https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml -o metrics-server.yaml
    
    echo "🔧 Patching for Vanilla K8s (Insecure TLS)..."
    # We use sed to insert the argument after the args: line
    sed -i '/- --metric-resolution=15s/a \        - --kubelet-insecure-tls' metrics-server.yaml
    
    echo "🚀 Applying Manifest..."
    kubectl apply -f metrics-server.yaml
    """
    return run_shell(script)

def check_metrics_server():
    """Checks if metrics API is available."""
    try:
        api = client.ApiextensionsV1Api()
        # This is a loose check, better to list apiservices
        res = subprocess.run("kubectl get apiservice v1beta1.metrics.k8s.io", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except:
        return False

def get_node_metrics():
    """Fetches metrics from metrics.k8s.io API."""
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
    except Exception as e:
        return []

# --- MAIN UI ---

st.title("☸️ Vanilla K8s Manager & Deployer")

tabs = st.tabs(["1. Cluster Management", "2. App Deployment", "3. Cluster Monitor", "4. Info"])

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
        
        # New: Detailed Node Table
        st.subheader("Cluster Nodes (Live Status)")
        if st.button("🔄 Refresh Node List"):
            st.rerun()
            
        nodes_data = get_detailed_nodes()
        if nodes_data:
            st.dataframe(nodes_data, use_container_width=True)
        else:
            st.info("No nodes detected (or check if Kubeconfig is loaded).")

        st.markdown("---")
        
        st.subheader("Add Worker Nodes")
        st.write("Generate configuration to add new VMs to this cluster.")
        
        # Worker OS Selection
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
                    st.download_button(
                        label="⬇️ Download user-data.yaml",
                        data=user_data,
                        file_name="worker-user-data.yaml",
                        mime="text/yaml",
                        help="Use this for cloud-init (AWS/Cloud Providers)"
                    )
                
                with c2:
                    st.download_button(
                        label="⬇️ Download worker-setup.sh",
                        data=bash_script,
                        file_name="worker-setup.sh",
                        mime="text/x-sh",
                        help="Run this script on the worker node as root"
                    )
            else:
                st.error("Could not generate token. Ensure you are running as sudo/root.")
                if error_msg:
                    st.code(error_msg, language="bash")
    else:
        st.warning(f"❌ Kubernetes Cluster is NOT initialized on this machine ({os_info['PRETTY_NAME']}).")
        
        if os_info['FAMILY'] == 'unknown':
            st.error("⚠️ Unknown OS family. Automatic installation might fail.")
            
        if st.button("🛠️ Install Master Node & Initialize Cluster"):
            # Create a placeholder for real-time terminal output
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

# --- TAB 2: APP DEPLOYMENT ---
with tabs[1]:
    st.header("App Deployment")
    
    # Connect Logic
    if 'connected' not in st.session_state:
        st.session_state['connected'] = False
        # Try auto-connect if running on master
        if ready:
             s, m = load_k8s_config()
             if s: st.session_state['connected'] = True

    if not st.session_state['connected']:
        if st.button("Connect to Local Cluster"):
            success, msg = load_k8s_config()
            if success:
                st.session_state['connected'] = True
                st.success("Connected!")
                st.rerun()
            else:
                st.error(msg)
    else:
        # --- NEW DASHBOARD SECTION ---
        st.subheader("📊 Live Workloads")
        if st.button("🔄 Refresh Apps"):
            st.rerun()
            
        workloads = get_active_workloads("default")
        
        if workloads:
            for app in workloads:
                with st.expander(f"{app['Name']} ({app['Ready']} Ready) - {app['Image']}"):
                    c1, c2 = st.columns([3, 1])
                    with c1:
                        st.write(f"**Age:** {app['Age']} days")
                        st.write(f"**Image:** {app['Image']}")
                    with c2:
                        if st.button("🗑️ Delete", key=f"del_{app['Name']}"):
                            logs = delete_app(app['Name'])
                            for log in logs: st.write(log)
                            time.sleep(1)
                            st.rerun()
        else:
            st.info("No active applications found in 'default' namespace.")
            
        st.markdown("---")
        
        # --- DEPLOYMENT SECTION ---
        st.subheader("🚀 Deploy New App")
        
        col1, col2 = st.columns(2)
        with col1:
            app_name = st.text_input("App Name", value="my-app")
            image_name = st.text_input("Image", value="nginx:latest")
        with col2:
            port = st.number_input("Port", value=80)
            replicas = st.number_input("Replicas", value=1)
            
        # VM Selection
        available_nodes = get_cluster_nodes()
        if available_nodes:
            target_nodes = st.multiselect("Select Target VMs", options=available_nodes)
        else:
            st.warning("No nodes found. Cluster might be empty.")
            target_nodes = []
        
        if st.button("🚀 Deploy"):
            try:
                logs = deploy_resources(app_name, image_name, port, replicas, "ClusterIP", "default", target_nodes)
                for log in logs: st.write(log)
                st.success("Done!")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")

# --- TAB 3: MONITOR ---
with tabs[2]:
    st.header("📊 Cluster Monitor")
    
    # Check Metrics Server
    has_metrics = check_metrics_server()
    
    if not has_metrics:
        st.warning("⚠️ Metrics Server is not installed or not ready.")
        st.caption("The Metrics Server is required to visualize CPU and Memory usage.")
        
        if st.button("🛠️ Install Metrics Server"):
            with st.spinner("Installing Metrics Server..."):
                success, log = install_metrics_server()
                if success:
                    st.success("Metrics Server Installed! Please wait 30-60s for it to start.")
                    st.rerun()
                else:
                    st.error(f"Installation Failed: {log}")
    else:
        st.success("✅ Metrics Server is Running")
        
        # Monitoring Control
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("▶️ Start Live Monitor"):
                st.session_state['monitoring'] = True
        with col2:
            if st.button("⏹️ Stop"):
                st.session_state['monitoring'] = False
        
        # Placeholders for Charts
        st.markdown("### 🖥️ Node Performance")
        cpu_chart = st.empty()
        mem_chart = st.empty()
        
        st.markdown("### 🌐 Master Node Network")
        net_chart = st.empty()
        
        # Monitoring Loop
        if st.session_state.get('monitoring', False):
            # Init history in session state if needed
            if 'cpu_history' not in st.session_state: st.session_state['cpu_history'] = []
            if 'mem_history' not in st.session_state: st.session_state['mem_history'] = []
            if 'net_history' not in st.session_state: st.session_state['net_history'] = []
            
            # We run a loop for a few iterations (Streamlit limits infinite loops)
            # User will just click start again or we use st.rerun() carefully
            for _ in range(30): # Run for ~60 seconds (2s interval)
                if not st.session_state.get('monitoring'): break
                
                # 1. Fetch K8s Metrics
                metrics = get_node_metrics()
                
                # Format for Streamlit Charts (List of Dicts)
                # We need a structure like: [{'Time': t, 'Node1': val, 'Node2': val}, ...]
                now = datetime.datetime.now().strftime("%H:%M:%S")
                
                cpu_row = {"Time": now}
                mem_row = {"Time": now}
                
                for m in metrics:
                    cpu_row[m['Name']] = m['CPU (cores)']
                    mem_row[m['Name']] = m['Memory (MiB)']
                
                # Update Charts
                st.session_state['cpu_history'].append(cpu_row)
                st.session_state['mem_history'].append(mem_row)
                
                # Keep buffer size reasonable
                if len(st.session_state['cpu_history']) > 50:
                    st.session_state['cpu_history'].pop(0)
                    st.session_state['mem_history'].pop(0)
                
                # Render Area Charts
                cpu_chart.area_chart(st.session_state['cpu_history'], x="Time", y=[k for k in cpu_row.keys() if k != "Time"])
                mem_chart.area_chart(st.session_state['mem_history'], x="Time", y=[k for k in mem_row.keys() if k != "Time"])
                
                # 2. Local Network Stats (Master Node Proxy)
                net = psutil.net_io_counters()
                net_row = {
                    "Time": now, 
                    "Sent (MB)": net.bytes_sent / 1024 / 1024,
                    "Recv (MB)": net.bytes_recv / 1024 / 1024
                }
                st.session_state['net_history'].append(net_row)
                if len(st.session_state['net_history']) > 50: st.session_state['net_history'].pop(0)
                
                net_chart.line_chart(st.session_state['net_history'], x="Time")
                
                time.sleep(2)
            
            # Loop ended naturally
            if st.session_state.get('monitoring'):
                st.rerun()

# --- TAB 4: INFO ---
with tabs[3]:
    st.header("ℹ️ Cluster Information & Requirements")
    
    st.markdown("### 🖥️ Minimal Hardware Requirements")
    hw_col1, hw_col2 = st.columns(2)
    with hw_col1:
        st.info("**Master Node**\n\n- 2 CPUs\n- 2 GB RAM\n- Swap Disabled")
    with hw_col2:
        st.info("**Worker Node**\n\n- 1 CPU\n- 1 GB RAM\n- Swap Disabled")

    st.markdown("---")
    st.markdown("### 🐧 Supported Operating Systems")
    st.info("**Debian** (11/12/Trixie), **Ubuntu** (20.04/22.04/24.04), **RHEL/CentOS** (8/9), **SUSE** (Leap/Tumbleweed)")
    st.caption("The installer automatically detects the OS and adjusts package managers (apt, dnf, zypper) accordingly.")
