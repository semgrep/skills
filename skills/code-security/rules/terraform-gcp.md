---
title: Secure GCP Terraform Configurations
impact: HIGH
---

## Secure GCP Terraform Configurations

**Impact: HIGH**

This guide provides secure configuration patterns for Google Cloud Platform (GCP) resources using Terraform. Following these best practices helps prevent misconfigurations that could lead to data exposure, unauthorized access, or compliance violations.

---

## Google Cloud Storage (GCS)

### Enable Uniform Bucket-Level Access

Uniform bucket-level access simplifies permission management by disabling object ACLs and using only IAM for access control.

**Incorrect (uniform bucket-level access disabled or not set):**

```hcl
# ruleid: gcp-storage-bucket-uniform-access
resource "google_storage_bucket" "default" {
  name     = "example.com"
  location = "EU"
}

# ruleid: gcp-storage-bucket-uniform-access
resource "google_storage_bucket" "disabled" {
  name     = "example"
  location = "EU"
  uniform_bucket_level_access = false
}
```

**Correct (uniform bucket-level access enabled):**

```hcl
# ok: gcp-storage-bucket-uniform-access
resource "google_storage_bucket" "enabled" {
  name     = "example"
  location = "EU"
  uniform_bucket_level_access = true
}
```

CWE-284: Improper Access Control

---

### Enable Cloud Storage Logging

Access logging helps with security auditing and compliance by tracking bucket access.

**Incorrect (logging not configured):**

```hcl
# ruleid: gcp-cloud-storage-logging
resource "google_storage_bucket" "fail" {
    name     = "jgwloggingbucket"
    location = var.location
    uniform_bucket_level_access = true
}
```

**Correct (logging configured):**

```hcl
# ok: gcp-cloud-storage-logging
resource "google_storage_bucket" "success" {
    name     = "jgwloggingbucket"
    location = var.location
    uniform_bucket_level_access = true
    logging {
        log_bucket = "mylovelybucket"
    }
}
```

CWE-778: Insufficient Logging

---

### Prevent Public Access to Storage Buckets

Storage buckets should not be publicly accessible to prevent data exposure.

**Incorrect (public access via IAM member):**

```hcl
# ruleid: gcp-storage-bucket-not-public-iam-member
resource "google_storage_bucket_iam_member" "fail" {
    bucket = google_storage_bucket.default.name
    role = "roles/storage.admin"
    member = "allUsers"
}
```

**Correct (access restricted to specific users):**

```hcl
# ok: gcp-storage-bucket-not-public-iam-member
resource "google_storage_bucket_iam_member" "success" {
    bucket = google_storage_bucket.default.name
    role = "roles/storage.admin"
    member = "user:jane@example.com"
}
```

**Incorrect (public access via IAM binding):**

```hcl
# ruleid: gcp-storage-bucket-not-public-iam-binding
resource "google_storage_bucket_iam_binding" "fail" {
    bucket = google_storage_bucket.default.name
    role = "roles/storage.admin"
    members = [
    "user:jane@example.com",
    "allAuthenticatedUsers"
    ]
}
```

**Correct (no public members in binding):**

```hcl
# ok: gcp-storage-bucket-not-public-iam-binding
resource "google_storage_bucket_iam_binding" "success" {
    bucket = google_storage_bucket.default.name
    role = "roles/storage.admin"
    members = [
    "user:jane@example.com"
    ]
}
```

CWE-284: Improper Access Control

---

### Enable Storage Versioning

Versioning protects against accidental deletion and enables recovery of previous versions.

**Incorrect (versioning disabled or not set):**

```hcl
# ruleid: gcp-storage-versioning-enabled
resource "google_storage_bucket" "fail1" {
  name     = "foo"
  location = "EU"

  versioning = {
    enabled = false
  }
}

# ruleid: gcp-storage-versioning-enabled
resource "google_storage_bucket" "fail2" {
  name     = "foo"
  location = "EU"
}
```

**Correct (versioning enabled):**

```hcl
# ok: gcp-storage-versioning-enabled
resource "google_storage_bucket" "pass" {
  name     = "foo"
  location = "EU"

  versioning = {
    enabled = true
  }
}
```

---

## Google Compute Engine (GCE)

### Encrypt Boot Disks with Customer-Managed Keys

Use Customer Supplied Encryption Keys (CSEK) or Cloud KMS keys to encrypt VM boot disks.

**Incorrect (no encryption key specified):**

```hcl
# ruleid: gcp-compute-boot-disk-encryption
resource "google_compute_instance" "fail" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
}
```

**Correct (encryption key specified):**

```hcl
# ok: gcp-compute-boot-disk-encryption
resource "google_compute_instance" "success" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {
        disk_encryption_key_raw = "acXTX3rxrKAFTF0tYVLvydU1riRZTvUNC4g5I11NY-c="
    }
}

# ok: gcp-compute-boot-disk-encryption
resource "google_compute_instance" "success" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {
        kms_key_self_link = google_kms_crypto_key.example-key.id
    }
}
```

CWE-311: Missing Encryption of Sensitive Data

---

### Encrypt Compute Disks with Customer-Managed Keys

Use Customer Supplied Encryption Keys (CSEK) or Cloud KMS keys to encrypt standalone disks.

**Incorrect (no encryption key specified):**

```hcl
# ruleid: gcp-compute-disk-encryption
resource "google_compute_disk" "fail" {
    name  = "test-disk"
    type  = "pd-ssd"
    zone  = "us-central1-a"
    image = "debian-8-jessie-v20170523"
    physical_block_size_bytes = 4096
}
```

**Correct (encryption key specified):**

```hcl
# ok: gcp-compute-disk-encryption
resource "google_compute_disk" "success" {
    name  = "test-disk"
    type  = "pd-ssd"
    zone  = "us-central1-a"
    image = "debian-8-jessie-v20170523"
    physical_block_size_bytes = 4096
    disk_encryption_key {
        raw_key = "acXTX3rxrKAFTF0tYVLvydU1riRZTvUNC4g5I11NY-c="
    }
}

# ok: gcp-compute-disk-encryption
resource "google_compute_disk" "success" {
    name  = "test-disk"
    type  = "pd-ssd"
    zone  = "us-central1-a"
    image = "debian-8-jessie-v20170523"
    physical_block_size_bytes = 4096
    disk_encryption_key {
        kms_key_self_link = google_kms_crypto_key.example-key.id
    }
}
```

CWE-311: Missing Encryption of Sensitive Data

---

### Prevent Public IP on Compute Instances

Compute instances should not have public IP addresses unless necessary.

**Incorrect (public IP via access_config):**

```hcl
# ruleid: gcp-compute-public-ip
resource "google_compute_instance" "fail" {
  name         = "test"
  machine_type = "n1-standard-1"
  zone         = "us-central1-a"
  boot_disk {
    auto_delete = true
  }

  network_interface {
    network = "default"
    access_config {
    }
  }
}
```

**Correct (no access_config block):**

```hcl
# ok: gcp-compute-public-ip
resource "google_compute_instance" "pass" {
  name         = "test"
  machine_type = "n1-standard-1"
  zone         = "us-central1-a"
  boot_disk {
    auto_delete = true
  }
  network_interface {

  }
}
```

CWE-284: Improper Access Control

---

### Disable Serial Port Access

Serial port access should be disabled to prevent unauthorized console access.

**Incorrect (serial port enabled):**

```hcl
# ruleid: gcp-compute-serial-ports
resource "google_compute_instance" "fail" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        serial-port-enable = true
    }
}
```

**Correct (serial port not enabled):**

```hcl
# ok: gcp-compute-serial-ports
resource "google_compute_instance" "success1" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
}

# ok: gcp-compute-serial-ports
resource "google_compute_instance" "success2" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        serial-port-enable = false
    }
}
```

CWE-284: Improper Access Control

---

### Enable OS Login

Do not override project-level OS Login settings at the instance level.

**Incorrect (OS Login disabled at instance level):**

```hcl
# ruleid: gcp-compute-os-login
resource "google_compute_instance" "fail" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        enable-oslogin = false
    }
}
```

**Correct (OS Login not overridden or enabled):**

```hcl
# ok: gcp-compute-os-login
resource "google_compute_instance" "success1" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        foo = "bar"
    }
}

# ok: gcp-compute-os-login
resource "google_compute_instance" "success2" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    metadata = {
        enable-oslogin = true
    }
}
```

CWE-284: Improper Access Control

---

### Disable IP Forwarding

IP forwarding should be disabled unless the instance is explicitly a router.

**Incorrect (IP forwarding enabled):**

```hcl
# ruleid: gcp-compute-ip-forward
resource "google_compute_instance" "fail" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    can_ip_forward = true
}
```

**Correct (IP forwarding disabled or not set):**

```hcl
# ok: gcp-compute-ip-forward
resource "google_compute_instance" "success" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
}

# ok: gcp-compute-ip-forward
resource "google_compute_instance" "success2" {
    name         = "gke-test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    can_ip_forward = false
}
```

CWE-284: Improper Access Control

---

### Enable Shielded VM

Shielded VMs provide verifiable integrity of your Compute Engine VM instances.

**Incorrect (shielded instance config not set or integrity monitoring disabled):**

```hcl
# ruleid: gcp-compute-shielded-vm
resource "google_compute_instance" "fail1" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
}

# ruleid: gcp-compute-shielded-vm
resource "google_compute_instance" "fail2" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    shielded_instance_config {
        enable_integrity_monitoring = false
    }
}
```

**Correct (shielded VM enabled with vTPM and integrity monitoring):**

```hcl
# ok: gcp-compute-shielded-vm
resource "google_compute_instance" "success" {
    name         = "test"
    machine_type = "n1-standard-1"
    zone         = "us-central1-a"
    boot_disk {}
    shielded_instance_config {
        enable_vtpm = true
        enable_integrity_monitoring = true
    }
}
```

---

## Google Compute Firewall

### Restrict SSH Access (Port 22)

SSH access should not be open to the entire internet (0.0.0.0/0).

**Incorrect (SSH open to world):**

```hcl
# ruleid: gcp-compute-firewall-unrestricted-ingress-22
resource "google_compute_firewall" "allow_ssh_int" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = [22]
  }

  source_ranges = ["0.0.0.0/0"]
}

# ruleid: gcp-compute-firewall-unrestricted-ingress-22
resource "google_compute_firewall" "allow_multiple" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = ["1024-65535", "22"]
  }

  source_ranges = ["0.0.0.0/0"]
}
```

**Correct (SSH restricted to specific IPs):**

```hcl
# ok: gcp-compute-firewall-unrestricted-ingress-22
resource "google_compute_firewall" "restricted" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["172.1.2.3/32"]
  target_tags   = ["ssh"]
}
```

CWE-284: Improper Access Control

---

### Restrict RDP Access (Port 3389)

RDP access should not be open to the entire internet (0.0.0.0/0).

**Incorrect (RDP open to world):**

```hcl
# ruleid: gcp-compute-firewall-unrestricted-ingress-3389
resource "google_compute_firewall" "allow_rdp_int" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = [3389]
  }

  source_ranges = ["0.0.0.0/0"]
}
```

**Correct (RDP restricted to specific IPs):**

```hcl
# ok: gcp-compute-firewall-unrestricted-ingress-3389
resource "google_compute_firewall" "restricted" {
  name    = "example"
  network = "google_compute_network.vpc.name"

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["172.1.2.3/32"]
}
```

CWE-284: Improper Access Control

---

## Google Kubernetes Engine (GKE)

### Disable Legacy ABAC Authorization

Legacy Attribute-Based Access Control (ABAC) should be disabled in favor of RBAC.

**Incorrect (legacy ABAC enabled):**

```hcl
# ruleid: gcp-gke-legacy-auth-enabled
resource "google_container_cluster" "fail" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  enable_legacy_abac = true
}
```

**Correct (legacy ABAC not enabled):**

```hcl
# ok: gcp-gke-legacy-auth-enabled
resource "google_container_cluster" "success" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
}
```

CWE-284: Improper Access Control

---

### Configure Private Cluster

GKE clusters should be configured as private clusters to restrict network access.

**Incorrect (no private cluster config):**

```hcl
# ruleid: gcp-gke-private-cluster-config
resource "google_container_cluster" "fail" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
}
```

**Correct (private cluster configured):**

```hcl
# ok: gcp-gke-private-cluster-config
resource "google_container_cluster" "success" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = false
    master_ipv4_cidr_block  = "10.0.0.0/28"
  }
}
```

CWE-284: Improper Access Control

---

### Enable Cluster Logging

GKE cluster logging should be enabled for security monitoring and audit.

**Incorrect (logging disabled):**

```hcl
# ruleid: gcp-gke-cluster-logging
resource "google_container_cluster" "fail" {
    name = "my-gke-cluster"
    location = "us-central1"
    remove_default_node_pool = true
    initial_node_count = 1
    logging_service = "none"
    master_auth  {
        username = ""
        password= ""
        client_certificate_config {
            issue_client_certificate = false
        }
    }
}
```

**Correct (default logging or explicitly enabled):**

```hcl
# ok: gcp-gke-cluster-logging
resource "google_container_cluster" "success" {
    name = "my-gke-cluster"
    location = "us-central1"
    remove_default_node_pool = true
    initial_node_count = 1
    master_auth {
        username = ""
        password = ""
        client_certificate_config {
            issue_client_certificate = false
        }
    }
}
```

CWE-320: Key Management Errors

---

### Enable Network Policy

Network policies should be enabled to control pod-to-pod communication.

**Incorrect (network policy disabled):**

```hcl
# ruleid: gcp-gke-network-policy-enabled
resource "google_container_cluster" "fail" {
  name = "google_cluster"
  network_policy {
    enabled = false
  }
}
```

**Correct (network policy enabled or using advanced datapath):**

```hcl
# ok: gcp-gke-network-policy-enabled
resource "google_container_cluster" "pass" {
  name = "google_cluster"
  network_policy {
    enabled = true
  }
}

# ok: gcp-gke-network-policy-enabled
resource "google_container_cluster" "pass2" {
  name              = "google_cluster"
  datapath_provider = "ADVANCED_DATAPATH"
  network_policy {
    enabled = false
  }
}
```

CWE-284: Improper Access Control

---

### Disable Basic Authentication

Basic authentication should be disabled in favor of more secure authentication methods.

**Incorrect (basic auth with username/password or no master_auth config):**

```hcl
# ruleid: gcp-gke-basic-auth
resource "google_container_cluster" "fail1" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3

  timeouts {
    create = "30m"
    update = "40m"
  }
}

# ruleid: gcp-gke-basic-auth
resource "google_container_cluster" "fail2" {
  name               = "google_cluster_bad"
  monitoring_service = "none"
  enable_legacy_abac = True
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "The world"
    }
  }

  master_auth {
    username = "test"
    password = "password"
  }

}
```

**Correct (basic auth disabled with empty credentials or client certificate config):**

```hcl
# ok: gcp-gke-basic-auth
resource "google_container_cluster" "pass" {
  name               = "google_cluster"
  monitoring_service = "monitoring.googleapis.com"
  master_authorized_networks_config {}
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
}

# ok: gcp-gke-basic-auth
resource "google_container_cluster" "pass2" {
  name               = "google_cluster"
  monitoring_service = "monitoring.googleapis.com"
  master_authorized_networks_config {}
  master_auth {
    username = ""
    password = ""
    client_certificate_config {
      issue_client_certificate = false
    }
  }
}
```

CWE-284: Improper Access Control

---

### Configure Master Authorized Networks

Master authorized networks restrict access to the Kubernetes API server.

**Incorrect (no master authorized networks):**

```hcl
# ruleid: gcp-gke-master-authz-networks-enabled
resource "google_container_cluster" "fail" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
}
```

**Correct (master authorized networks configured):**

```hcl
# ok: gcp-gke-master-authz-networks-enabled
resource "google_container_cluster" "success" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "73.35.171.194/32"
      display_name = "net1"
    }
  }
}
```

CWE-284: Improper Access Control

---

### Enable Monitoring

GKE cluster monitoring should be enabled for visibility and alerting.

**Incorrect (monitoring disabled):**

```hcl
# ruleid: gcp-gke-monitoring-enabled
resource "google_container_cluster" "fail" {
    name = "my-gke-cluster"
    location = "us-central1"
    monitoring_service = "none"
  }
```

**Correct (monitoring enabled):**

```hcl
# ok: gcp-gke-monitoring-enabled
resource "google_container_cluster" "success" {
  name = "my-gke-cluster"
  location = "us-central1"
  monitoring_service = "monitoring.googleapis.com"
}
```

CWE-284: Improper Access Control

---

### Disable Client Certificate Authentication

Client certificate authentication should be disabled for GKE clusters.

**Incorrect (client certificate enabled):**

```hcl
# ruleid: gcp-gke-client-certificate-disabled
resource "google_container_cluster" "success" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  master_auth {
    client_certificate_config {
        issue_client_certificate = true
    }
  }
}
```

**Correct (client certificate disabled):**

```hcl
# ok: gcp-gke-client-certificate-disabled
resource "google_container_cluster" "fail" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  master_auth {
    client_certificate_config {
        issue_client_certificate = false
    }
  }
}
```

CWE-284: Improper Access Control

---

### Enable VPC Flow Logs and Intranode Visibility

VPC Flow Logs and intranode visibility help with network monitoring and troubleshooting.

**Incorrect (intranode visibility not enabled):**

```hcl
# ruleid: gcp-gke-enabled-vpc-flow-logs
resource "google_container_cluster" "fail" {
  name               = var.name
  location           = var.location
  initial_node_count = 1
  project            = data.google_project.project.name

  network    = var.network
  subnetwork = var.subnetwork
  # enable_intranode_visibility not set
}
```

**Correct (intranode visibility enabled):**

```hcl
# ok: gcp-gke-enabled-vpc-flow-logs
resource "google_container_cluster" "success" {
  name               = var.name
  location           = var.location
  initial_node_count = 1
  project            = data.google_project.project.name

  network                     = var.network
  subnetwork                  = var.subnetwork
  enable_intranode_visibility = true
}
```

CWE-284: Improper Access Control

---

### Enable Binary Authorization

Binary Authorization ensures only trusted container images are deployed.

**Incorrect (binary authorization disabled):**

```hcl
# ruleid: gcp-gke-binary-authorization
resource "google_container_cluster" "fail1" {
  name               = var.name
  location           = var.location
  initial_node_count = 1

  enable_binary_authorization = false
}
```

**Correct (binary authorization enabled):**

```hcl
# ok: gcp-gke-binary-authorization
resource "google_container_cluster" "success" {
  name                        = var.name
  location                    = var.location
  initial_node_count          = 1
  enable_binary_authorization = true
}
```

---

### Enable Shielded Nodes

Shielded GKE nodes provide verifiable node identity and integrity.

**Incorrect (shielded nodes disabled):**

```hcl
# ruleid: gcp-gke-enable-shielded-nodes
resource "google_container_cluster" "fail" {
  name               = var.name
  location           = var.location
  initial_node_count = 1

  enable_shielded_nodes = false
}
```

**Correct (shielded nodes enabled or default):**

```hcl
# ok: gcp-gke-enable-shielded-nodes
resource "google_container_cluster" "success2" {
  name               = var.name
  location           = var.location
  initial_node_count = 1

  enable_shielded_nodes = true
}
```

---

### Enable Node Pool Auto-Repair

Auto-repair automatically fixes unhealthy nodes.

**Incorrect (auto-repair disabled):**

```hcl
# ruleid: gcp-gke-nodepool-auto-repair-enabled
resource "google_container_node_pool" "fail" {
    name = "my-gke-cluster"
    location = "us-central1"
    cluster = "my-cluster"
    management {
      auto_repair  = false
      auto_upgrade = false
    }
}
```

**Correct (auto-repair enabled):**

```hcl
# ok: gcp-gke-nodepool-auto-repair-enabled
resource "google_container_node_pool" "success" {
  name = "my-gke-cluster"
  location = "us-central1"
  cluster = "my-cluster"
  management {
    auto_repair  = true
    auto_upgrade = true
  }
}
```

---

## Cloud SQL

### Require SSL for Database Connections

All Cloud SQL database connections should require SSL encryption.

**Incorrect (SSL not required):**

```hcl
# ruleid: gcp-sql-database-require-ssl
resource "google_sql_database_instance" "fail" {
  database_version = "MYSQL_8_0"
  name             = "instance"
  region           = "us-central1"
  settings {
    tier = "db-f1-micro"
  }
}
```

**Correct (SSL required):**

```hcl
# ok: gcp-sql-database-require-ssl
resource "google_sql_database_instance" "success" {
  database_version = "MYSQL_8_0"
  name             = "instance"
  region           = "us-central1"
  ip_configuration {
      ipv4_enabled = true
      require_ssl = true
  }
}
```

CWE-326: Inadequate Encryption Strength

---

### Prevent Public Database Access

Cloud SQL instances should not be accessible from 0.0.0.0/0.

**Incorrect (public access via 0.0.0.0/0):**

```hcl
# ruleid: gcp-sql-public-database
resource "google_sql_database_instance" "instance1-fail" {
  database_version = "MYSQL_8_0"
  name             = "instance"
  region           = "us-central1"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "XYZ"
        value = "1.2.3.4"
      }
      authorized_networks {
        name  = "Public"
        value = "0.0.0.0/0"
      }
    }
  }
}
```

**Correct (restricted to specific IPs or private network):**

```hcl
# ok: gcp-sql-public-database
resource "google_sql_database_instance" "instance2-pass" {
  database_version = "MYSQL_8_0"
  name             = "instance"
  region           = "us-central1"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "XYZ"
        value = "1.2.3.4"
      }
      authorized_networks {
        name  = "ABC"
        value = "5.5.5.0/24"
      }
    }
  }
}

# ok: gcp-sql-public-database
resource "google_sql_database_instance" "instance6-pass" {
  provider = google-beta

  name   = "private-instance-${random_id.db_name_suffix.hex}"
  region = "us-central1"

  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.private_network.id
    }
  }
}
```

CWE-284: Improper Access Control

---

### Disable Public IP for SQL Server

SQL Server instances should not have public IPs.

**Incorrect (public IP enabled for SQL Server):**

```hcl
# ruleid: gcp-sqlserver-no-public-ip
resource "google_sql_database_instance" "fail" {
  database_version = "SQLSERVER_2017_STANDARD"
  name             = "general-sqlserver12"
  region           = "us-central1"

  settings {
    tier = "db-custom-1-4096"

    ip_configuration {
      ipv4_enabled    = true
      private_network = "projects/gcp-bridgecrew-deployment/global/networks/default"
      require_ssl     = "false"
    }
  }
}
```

**Correct (public IP disabled):**

```hcl
# ok: gcp-sqlserver-no-public-ip
resource "google_sql_database_instance" "pass" {
  database_version = "SQLSERVER_2017_STANDARD"
  name             = "general-sqlserver12"
  region           = "us-central1"

  settings {
    tier = "db-custom-1-4096"

    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/gcp-bridgecrew-deployment/global/networks/default"
    }
  }
}
```

CWE-284: Improper Access Control

---

### Enable PostgreSQL Connection Logging

PostgreSQL instances should log connections for auditing.

**Incorrect (log_connections flag set to off):**

```hcl
# ruleid: gcp-postgresql-log-connection
resource "google_sql_database_instance" "fail" {
  database_version = "POSTGRES_12"
  name             = "general-pos121"
  region           = "us-central1"
  settings {
    database_flags {
      name  = "log_connections"
      value = "off"
    }
    tier = "db-custom-1-3840"
  }
}
```

**Correct (log_connections flag set to on):**

```hcl
# ok: gcp-postgresql-log-connection
resource "google_sql_database_instance" "pass1" {
  database_version = "POSTGRES_12"
  name             = "general-pos121"
  region           = "us-central1"
  settings {
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    tier         = "db-custom-1-3840"
  }
}
```

---

## IAM

### Avoid Default Service Account at Project Level

Default service accounts should not be used at the project level.

**Incorrect (default service account used):**

```hcl
# ruleid: gcp-project-member-default-service-account-iam-member
resource "google_project_iam_member" "fail" {
    project = "your-project-id"
    role    = "roles/resourcemanager.organizationAdmin"
    member  = "serviceAccount:test-compute@developer.gserviceaccount.com"
}
```

**Correct (specific user or service account):**

```hcl
# ok: gcp-project-member-default-service-account-iam-member
resource "google_project_iam_member" "success" {
    project = "your-project-id"
    role    = "roles/other"
    member  = "user@mail.com"
}
```

CWE-284: Improper Access Control

---

### Avoid Service Account User/Token Creator Roles at Project Level

Users should not be assigned Service Account User or Service Account Token Creator roles at the project level.

**Incorrect (dangerous SA roles assigned):**

```hcl
# ruleid: gcp-project-service-account-user-iam-member
resource "google_project_iam_member" "fail1" {
    project = "your-project-id"
    role    = "roles/iam.serviceAccountTokenCreator"
    member  = "user:jane@example.com"
}

# ruleid: gcp-project-service-account-user-iam-member
resource "google_project_iam_member" "fail2" {
    project = "your-project-id"
    role    = "roles/iam.serviceAccountUser"
    member  = "user:jane@example.com"
}
```

**Correct (appropriate roles assigned):**

```hcl
# ok: gcp-project-service-account-user-iam-member
resource "google_project_iam_member" "success" {
    project = "your-project-id"
    role    = "roles/editor"
    member  = "user:jane@example.com"
}
```

CWE-284: Improper Access Control

---

## VPC and Networking

### Enable VPC Flow Logs for Subnets

VPC Flow Logs provide visibility into network traffic for analysis and troubleshooting.

**Incorrect (no log_config):**

```hcl
# ruleid: gcp-sub-network-logging-enabled
resource "google_compute_subnetwork" "default" {
  name          = "example"
  ip_cidr_range = "10.0.0.0/16"
  network       = "google_compute_network.vpc.id"
}
```

**Correct (log_config configured):**

```hcl
# ok: gcp-sub-network-logging-enabled
resource "google_compute_subnetwork" "enabled" {
  name          = "example"
  ip_cidr_range = "10.0.0.0/16"
  network       = "google_compute_network.vpc.self_link"

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
```

CWE-284: Improper Access Control

---

### Disable Default Network for Projects

Projects should not use the auto-created default network.

**Incorrect (default network auto-created):**

```hcl
# ruleid: gcp-project-default-network
resource "google_project" "fail" {
    name       = "My Project"
    project_id = "your-project-id"
    org_id     = "1234567"
}
```

**Correct (default network disabled):**

```hcl
# ok: gcp-project-default-network
resource "google_project" "pass" {
    name       = "My Project"
    project_id = "your-project-id"
    org_id     = "1234567"
    auto_create_network   = false
}
```

CWE-284: Improper Access Control

---

## Cloud KMS

### Protect KMS Keys from Deletion

KMS keys should have lifecycle protection to prevent accidental deletion.

**Incorrect (prevent_destroy not set or false):**

```hcl
# ruleid: gcp-kms-prevent-destroy
resource "google_kms_crypto_key" "fail" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "15552000s"

  lifecycle {
    prevent_destroy = false
  }
}

# ruleid: gcp-kms-prevent-destroy
resource "google_kms_crypto_key" "fail2" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "15552000s"
}
```

**Correct (prevent_destroy enabled):**

```hcl
# ok: gcp-kms-prevent-destroy
resource "google_kms_crypto_key" "pass" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "15552000s"

  lifecycle {
    prevent_destroy = true
  }
}
```

CWE-284: Improper Access Control

---

## Memorystore (Redis)

### Enable Redis Authentication

Memorystore for Redis instances should have authentication enabled.

**Incorrect (auth not enabled):**

```hcl
# ruleid: gcp-memory-store-for-redis-auth-enabled
resource "google_redis_instance" "fail1" {
  name           = "my-fail-instance1"
  tier           = "STANDARD_HA"
  memory_size_gb = 1

  location_id             = "us-central1-a"
  alternative_location_id = "us-central1-f"

  redis_version = "REDIS_4_0"
  display_name  = "I am insecure"
}

# ruleid: gcp-memory-store-for-redis-auth-enabled
resource "google_redis_instance" "fail2" {
  name           = "my-fail-instance2"
  memory_size_gb = 1
  auth_enabled = false
}
```

**Correct (auth enabled):**

```hcl
# ok: gcp-memory-store-for-redis-auth-enabled
resource "google_redis_instance" "pass" {
  name           = "my-pass-instance"
  memory_size_gb = 1
  tier           = "STANDARD_HA"

  location_id             = "us-central1-a"
  alternative_location_id = "us-central1-f"
  redis_version           = "REDIS_6_X"

  labels = {
    foo = "bar"
  }

  auth_enabled = true
}
```

CWE-284: Improper Access Control

---

### Enable Redis In-Transit Encryption

Memorystore for Redis should use in-transit encryption.

**Incorrect (transit encryption disabled or not set):**

```hcl
# ruleid: gcp-memory-store-for-redis-intransit-encryption
resource "google_redis_instance" "fail" {
  provider       = google-beta
  name           = "mrr-memory-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5

  redis_version      = "REDIS_6_X"
  display_name       = "Terraform Test Instance"
}

# ruleid: gcp-memory-store-for-redis-intransit-encryption
resource "google_redis_instance" "fail2" {
  provider       = google-beta
  name           = "mrr-memory-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5

  transit_encryption_mode = "DISABLED"
}
```

**Correct (transit encryption enabled):**

```hcl
# ok: gcp-memory-store-for-redis-intransit-encryption
resource "google_redis_instance" "pass" {
  provider       = google-beta
  name           = "mrr-memory-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 5

  redis_version      = "REDIS_6_X"
  display_name       = "Terraform Test Instance"

  transit_encryption_mode = "SERVER_AUTHENTICATION"
}
```

CWE-284: Improper Access Control

---

## Cloud Run

### Prevent Public Access to Cloud Run Services

Cloud Run services should not be publicly accessible unless necessary.

**Incorrect (public access via allUsers or allAuthenticatedUsers):**

```hcl
# ruleid: gcp-run-private-service-iam-member
resource "google_cloud_run_service_iam_member" "fail1" {
  location = google_cloud_run_service.default.location
  service = google_cloud_run_service.default.name
  role = "roles/viewer"
  member  = "allAuthenticatedUsers"
}

# ruleid: gcp-run-private-service-iam-member
resource "google_cloud_run_service_iam_member" "fail2" {
  location = google_cloud_run_service.default.location
  service = google_cloud_run_service.default.name
  role = "roles/viewer"
  member  = "allUsers"
}
```

**Correct (access restricted to specific users):**

```hcl
# ok: gcp-run-private-service-iam-member
resource "google_cloud_run_service_iam_member" "pass1" {
  location = google_cloud_run_service.default.location
  service = google_cloud_run_service.default.name
  role = "roles/viewer"
  member = "user:jane@example.com"
}

# ok: gcp-run-private-service-iam-member
resource "google_cloud_run_service_iam_member" "pass2" {
  location = google_cloud_run_service.default.location
  service = google_cloud_run_service.default.name
  role = "roles/viewer"
  member = "domain:example.com"
}
```

CWE-284: Improper Access Control

---

## Cloud Build

### Make Cloud Build Workers Private

Cloud Build worker pools should not have external IP addresses.

**Incorrect (external IP enabled or not set):**

```hcl
# ruleid: gcp-build-workers-private
resource "google_cloudbuild_worker_pool" "fail1" {
  name = "my-pool"
  location = "europe-west1"
  worker_config {
    disk_size_gb = 100
    machine_type = "e2-standard-4"
    no_external_ip = false
  }
}

# ruleid: gcp-build-workers-private
resource "google_cloudbuild_worker_pool" "fail2" {
  name = "my-pool"
  location = "europe-west1"
  worker_config {
    disk_size_gb = 100
    machine_type = "e2-standard-4"
  }
}
```

**Correct (no external IP):**

```hcl
# ok: gcp-build-workers-private
resource "google_cloudbuild_worker_pool" "pass" {
  name = "my-pool"
  location = "europe-west1"
  worker_config {
    disk_size_gb = 100
    machine_type = "e2-standard-4"
    no_external_ip = true
  }
}
```

CWE-284: Improper Access Control

---

## BigQuery

### Encrypt BigQuery Datasets with Customer-Managed Keys

BigQuery datasets should use customer-managed encryption keys.

**Incorrect (no encryption configuration):**

```hcl
# ruleid: gcp-bigquery-dataset-encrypted-with-cmk
resource "google_bigquery_dataset" "fail" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  description                 = "This is a test description"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    env = "default"
  }

  access {
    role          = "OWNER"
    special_group = "allAuthenticatedUsers"
  }
}
```

**Correct (encryption configured with KMS key):**

```hcl
# ok: gcp-bigquery-dataset-encrypted-with-cmk
resource "google_bigquery_dataset" "pass" {
  dataset_id                  = var.dataset.dataset_id
  friendly_name               = var.dataset.friendly_name
  description                 = var.dataset.description
  location                    = var.location
  default_table_expiration_ms = var.dataset.default_table_expiration_ms

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.example.name
  }
}
```

CWE-320: Key Management Errors

---

## Pub/Sub

### Encrypt Pub/Sub Topics with Customer-Managed Keys

Pub/Sub topics should use customer-managed encryption keys.

**Incorrect (no KMS key specified):**

```hcl
# ruleid: gcp-pubsub-encrypted-with-cmk
resource "google_pubsub_topic" "fail" {
  name = "example-topic"
}
```

**Correct (KMS key specified):**

```hcl
# ok: gcp-pubsub-encrypted-with-cmk
resource "google_pubsub_topic" "pass" {
  name         = "example-topic"
  kms_key_name = google_kms_crypto_key.crypto_key.id
}
```

CWE-320: Key Management Errors

---

## Artifact Registry

### Encrypt Artifact Registry with Customer-Managed Keys

Artifact Registry repositories should use customer-managed encryption keys.

**Incorrect (no KMS key specified):**

```hcl
# ruleid: gcp-artifact-registry-encrypted-with-cmk
resource "google_artifact_registry_repository" "fail" {
  provider = google-beta

  location      = "us-central1"
  repository_id = "my-repository"
  description   = "example docker repository with cmek"
  format        = "DOCKER"
}
```

**Correct (KMS key specified):**

```hcl
# ok: gcp-artifact-registry-encrypted-with-cmk
resource "google_artifact_registry_repository" "pass" {
  provider = google-beta

  location      = "us-central1"
  repository_id = "my-repository"
  description   = "example docker repository with cmek"
  format        = "DOCKER"
  kms_key_name  = google_kms_crypto_key.example.name
}
```

CWE-320: Key Management Errors

---

## Dataproc

### Make Dataproc Clusters Private

Dataproc clusters should not have public IP addresses.

**Incorrect (internal_ip_only not set or false):**

```hcl
# ruleid: gcp-dataproc-cluster-public-ip
resource "google_dataproc_cluster" "fail1" {
  name   = "my-fail1-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      zone = "us-central1-a"
      # "internal_ip_only" does not exist
      # and the default is public IPs
    }
  }
}

# ruleid: gcp-dataproc-cluster-public-ip
resource "google_dataproc_cluster" "fail2" {
  name   = "my-fail2-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      zone = "us-central1-a"
      internal_ip_only = false
    }
  }
}
```

**Correct (internal_ip_only set to true):**

```hcl
# ok: gcp-dataproc-cluster-public-ip
resource "google_dataproc_cluster" "pass1" {
  name   = "my-pass-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      zone = "us-central1-a"
      # no public IPs
      internal_ip_only = true
    }
  }
}
```

CWE-284: Improper Access Control

---

## Vertex AI

### Make Vertex AI Instances Private

Vertex AI notebook instances should not have public IP addresses.

**Incorrect (no_public_ip not set or false):**

```hcl
# ruleid: gcp-vertexai-private-instance
resource "google_notebooks_instance" "fail1" {
  name = "fail1-instance"
  location = "us-west1-a"
  machine_type = "e2-medium"
  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
  no_public_ip = false
}

# ruleid: gcp-vertexai-private-instance
resource "google_notebooks_instance" "fail2" {
  name = "fail2-instance"
  location = "us-west1-a"
  machine_type = "e2-medium"
  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
}
```

**Correct (no_public_ip set to true):**

```hcl
# ok: gcp-vertexai-private-instance
resource "google_notebooks_instance" "pass1" {
  name = "pass1-instance"
  location = "us-west1-a"
  machine_type = "e2-medium"
  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
  no_public_ip = true
}
```

CWE-284: Improper Access Control

---

## Cloud DNS

### Avoid RSASHA1 for DNSSEC

RSASHA1 is a weak algorithm and should not be used for DNSSEC.

**Incorrect (RSASHA1 algorithm used):**

```hcl
# ruleid: gcp-dns-key-specs-rsasha1
resource "google_dns_managed_zone" "fail" {
    name        = "example-zone"
    dns_name    = "example-de13he3.com."
    description = "Example DNS zone"
    dnssec_config {
        state = on
        default_key_specs {
            algorithm  = "rsasha1"
            key_length = 1024
            key_type   = "zoneSigning"
        }
        default_key_specs {
            algorithm = "rsasha1"
            key_length = 2048
            key_type = "keySigning"
        }
    }
}
```

**Correct (stronger algorithm used):**

```hcl
# ok: gcp-dns-key-specs-rsasha1
resource "google_dns_managed_zone" "success" {
    name        = "example-zone"
    dns_name    = "example-de13he3.com."
    description = "Example DNS zone"
    dnssec_config {
        state = on
        default_key_specs {
            algorithm  = "rsasha256"
            key_length = 1024
            key_type   = "zoneSigning"
        }
        default_key_specs {
            algorithm = "rsasha256"
            key_length = 2048
            key_type = "keySigning"
        }
    }
}
```

CWE-326: Inadequate Encryption Strength

---

## Load Balancer SSL Policies

### Enforce TLS 1.2 Minimum

Load balancer SSL policies should require TLS 1.2 or higher.

**Incorrect (TLS 1.0 or 1.1 allowed):**

```hcl
# ruleid: gcp-insecure-load-balancer-tls-version
resource "google_compute_ssl_policy" "badCode" {
  name = "badCode"
  min_tls_version = "TLS_1_0"
}
```

**Correct (TLS 1.2 minimum):**

```hcl
# ok: gcp-insecure-load-balancer-tls-version
resource "google_compute_ssl_policy" "okCode" {
  name = "okCode"
  min_tls_version = "TLS_1_2"
}
```

CWE-326: Inadequate Encryption Strength

---

### Avoid Weak Cipher Suites

SSL policies should not allow weak cipher suites.

**Incorrect (weak ciphers allowed or min_tls_version not set):**

```hcl
# ruleid: gcp-compute-ssl-policy
resource "google_compute_ssl_policy" "fail1" {
    name            = "nonprod-ssl-policy"
    profile         = "MODERN"
}

# ruleid: gcp-compute-ssl-policy
resource "google_compute_ssl_policy" "fail2" {
    name            = "custom-ssl-policy"
    min_tls_version = "TLS_1_2"
    profile         = "CUSTOM"
    custom_features = ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384"]
}
```

**Correct (strong ciphers only with TLS 1.2):**

```hcl
# ok: gcp-compute-ssl-policy
resource "google_compute_ssl_policy" "success1" {
    name            = "nonprod-ssl-policy"
    profile         = "MODERN"
    min_tls_version = "TLS_1_2"
}

# ok: gcp-compute-ssl-policy
resource "google_compute_ssl_policy" "success1" {
    name            = "custom-ssl-policy"
    min_tls_version = "TLS_1_2"
    profile         = "CUSTOM"
    custom_features = ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
}
```

CWE-326: Inadequate Encryption Strength

---

## References

- [Google Cloud Security Best Practices](https://cloud.google.com/security/best-practices)
- [CIS Google Cloud Platform Foundation Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [Terraform Google Provider Documentation](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [OWASP Top 10](https://owasp.org/Top10/)
