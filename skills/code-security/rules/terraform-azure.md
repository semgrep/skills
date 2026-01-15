---
title: Secure Azure Terraform Configurations
impact: HIGH
---

## Secure Azure Terraform Configurations

This guide documents security best practices for Azure infrastructure provisioned via Terraform. Misconfigurations in cloud infrastructure can lead to data breaches, unauthorized access, and compliance violations.

**Incorrect (Azure Storage - TLS version missing or outdated):**

```hcl
# ruleid: storage-use-secure-tls-policy
resource "azurerm_storage_account" "bad_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
}

# ruleid: storage-use-secure-tls-policy
resource "azurerm_storage_account" "bad_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_0"
}
```

**Correct (Azure Storage - TLS 1.2 enforced):**

```hcl
resource "azurerm_storage_account" "good_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_2"
}
```

**Incorrect (Azure Storage - network rules allow all traffic):**

```hcl
# ruleid: storage-default-action-deny
resource "azurerm_storage_account_network_rules" "bad_example" {
  default_action             = "Allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
```

**Correct (Azure Storage - network rules deny by default):**

```hcl
resource "azurerm_storage_account_network_rules" "good_example" {
  default_action             = "Deny"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
```

**Incorrect (Azure Storage - HTTP traffic allowed):**

```hcl
# ruleid: storage-enforce-https
resource "azurerm_storage_account" "bad_example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = false
}
```

**Correct (Azure Storage - HTTPS only):**

```hcl
resource "azurerm_storage_account" "good_example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = true
}
```

**Incorrect (Azure Storage - queue logging not configured):**

```hcl
# ruleid: storage-queue-services-logging
resource "azurerm_storage_account" "bad_example" {
    name                     = "example"
    resource_group_name      = data.azurerm_resource_group.example.name
    location                 = data.azurerm_resource_group.example.location
    account_tier             = "Standard"
    account_replication_type = "GRS"
    queue_properties  {
  }
}
```

**Correct (Azure Storage - queue logging enabled):**

```hcl
resource "azurerm_storage_account" "good_example" {
    name                     = "example"
    resource_group_name      = data.azurerm_resource_group.example.name
    location                 = data.azurerm_resource_group.example.location
    account_tier             = "Standard"
    account_replication_type = "GRS"
    queue_properties  {
    logging {
        delete                = true
        read                  = true
        write                 = true
        version               = "1.0"
        retention_policy_days = 10
    }
  }
}
```

**Incorrect (Azure Storage - missing AzureServices bypass):**

```hcl
# ruleid: storage-allow-microsoft-service-bypass
resource "azurerm_storage_account" "bad_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
      bypass                     = ["Metrics"]
  }
}
```

**Correct (Azure Storage - AzureServices bypass included):**

```hcl
resource "azurerm_storage_account" "good_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
    bypass                     = ["Metrics", "AzureServices"]
  }
}
```

**Incorrect (Azure Storage - blob container public access):**

```hcl
# ruleid: azure-storage-blob-service-container-private-access
resource "azurerm_storage_container" "example" {
    name                  = "vhds"
    storage_account_name  = azurerm_storage_account.example.name
    container_access_type = "blob"
}
```

**Correct (Azure Storage - blob container private access):**

```hcl
resource "azurerm_storage_container" "example" {
    name                  = "vhds"
    storage_account_name  = azurerm_storage_account.example.name
    container_access_type = "private"
}
```

**Incorrect (Azure App Service - outdated TLS version):**

```hcl
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    # ruleid: appservice-use-secure-tls-policy
      min_tls_version = "1.0"
  }
}
```

**Correct (Azure App Service - TLS 1.2):**

```hcl
resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
      min_tls_version = "1.2"
  }
}
```

**Incorrect (Azure App Service - HTTPS not enforced):**

```hcl
# ruleid: appservice-enable-https-only
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
  https_only          = false
}

# ruleid: appservice-enable-https-only
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}
```

**Correct (Azure App Service - HTTPS enforced):**

```hcl
resource "azurerm_app_service" "good_example" {
    name                       = "example-app-service"
    location                   = azurerm_resource_group.example.location
    resource_group_name        = azurerm_resource_group.example.name
    app_service_plan_id        = azurerm_app_service_plan.example.id
    https_only                 = true
}
```

**Incorrect (Azure App Service - authentication disabled):**

```hcl
# ruleid: appservice-authentication-enabled
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}

# ruleid: appservice-authentication-enabled
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  auth_settings {
    enabled = false
  }
}
```

**Correct (Azure App Service - authentication enabled):**

```hcl
resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  auth_settings {
    enabled = true
  }
}
```

**Incorrect (Azure App Service - remote debugging enabled):**

```hcl
# ruleid: azure-remote-debugging-not-enabled
resource "azurerm_app_service" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    app_service_plan_id = azurerm_app_service_plan.example.id

    site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    }
    remote_debugging_enabled = true
}
```

**Correct (Azure App Service - remote debugging disabled):**

```hcl
resource "azurerm_app_service" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    app_service_plan_id = azurerm_app_service_plan.example.id

    site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    }
    remote_debugging_enabled = false
}
```

**Incorrect (Azure App Service - wildcard CORS origin):**

```hcl
resource "azurerm_app_service" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    app_service_plan_id = azurerm_app_service_plan.example.id

    site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    cors {
        # ruleid: azure-appservice-disallowed-cors
        allowed_origins = ["*"]
    }
    }
}
```

**Correct (Azure App Service - specific CORS origins):**

```hcl
resource "azurerm_app_service" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    app_service_plan_id = azurerm_app_service_plan.example.id

    site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    cors {
        allowed_origins = ["192.0.0.1"]
    }
    }
}
```

**Incorrect (Azure Function App - authentication disabled):**

```hcl
# ruleid: functionapp-authentication-enabled
resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id
}

# ruleid: functionapp-authentication-enabled
resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id

  auth_settings {
    enabled = false
  }
}
```

**Correct (Azure Function App - authentication enabled):**

```hcl
resource "azurerm_function_app" "good_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id

  auth_settings {
    enabled = true
  }
}
```

**Incorrect (Azure Function App - wildcard CORS):**

```hcl
resource "azurerm_function_app" "example" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  site_config {
    cors {
        # ruleid: azure-functionapp-disallow-cors
        allowed_origins = ["*"]
    }
  }
}
```

**Correct (Azure Function App - specific CORS origins):**

```hcl
resource "azurerm_function_app" "example" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  site_config {
    cors {
        allowed_origins = ["192.0.0.1"]
    }
  }
}
```

**Incorrect (Azure Key Vault - network ACLs missing or allow default):**

```hcl
# ruleid: keyvault-specify-network-acl
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false
}

# ruleid: keyvault-specify-network-acl
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false

    network_acls {
        bypass = "AzureServices"
        default_action = "Allow"
    }
}
```

**Correct (Azure Key Vault - network ACLs with deny default):**

```hcl
resource "azurerm_key_vault" "good_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.good_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false

    network_acls {
        bypass = "AzureServices"
        default_action = "Deny"
    }
}
```

**Incorrect (Azure Key Vault - purge protection disabled):**

```hcl
# ruleid: keyvault-purge-enabled
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    purge_protection_enabled    = false
}

# ruleid: keyvault-purge-enabled
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
}
```

**Correct (Azure Key Vault - purge protection enabled):**

```hcl
resource "azurerm_key_vault" "good_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.good_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = true
}
```

**Incorrect (Azure Key Vault - key without expiration date):**

```hcl
# ruleid: keyvault-ensure-key-expires
resource "azurerm_key_vault_key" "bad_example" {
  name         = "generated-certificate"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
```

**Correct (Azure Key Vault - key with expiration date):**

```hcl
resource "azurerm_key_vault_key" "good_example" {
  name         = "generated-certificate"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  expiration_date = "1982-12-31T00:00:00Z"

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
```

**Incorrect (Azure SQL Server - public network access enabled):**

```hcl
# ruleid: azure-sqlserver-public-access-disabled
resource "azurerm_mssql_server" "example" {
    name                         = "mssqlserver"
    resource_group_name          = azurerm_resource_group.example.name
    location                     = azurerm_resource_group.example.location
    version                      = "12.0"
    administrator_login          = "missadministrator"
    administrator_login_password = "thisIsKat11"
    minimum_tls_version          = "1.2"
    public_network_access_enabled = true
    azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
    }
}

# ruleid: azure-sqlserver-public-access-disabled
resource "azurerm_mssql_server" "example" {
    name                         = "mssqlserver"
    resource_group_name          = azurerm_resource_group.example.name
    location                     = azurerm_resource_group.example.location
    version                      = "12.0"
    administrator_login          = "missadministrator"
    administrator_login_password = "thisIsKat11"
    minimum_tls_version          = "1.2"
    azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
    }
}
```

**Correct (Azure SQL Server - public network access disabled):**

```hcl
resource "azurerm_mssql_server" "example" {
    name                         = "mssqlserver"
    resource_group_name          = azurerm_resource_group.example.name
    location                     = azurerm_resource_group.example.location
    version                      = "12.0"
    administrator_login          = "missadministrator"
    administrator_login_password = "thisIsKat11"
    minimum_tls_version          = "1.2"
    public_network_access_enabled = false
    azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
    }
}
```

**Incorrect (Azure MSSQL - outdated TLS version):**

```hcl
resource "azurerm_mssql_server" "examplea" {
    name                          = var.server_name
    resource_group_name           = var.resource_group.name
    location                      = var.resource_group.location
    version                       = var.sql["version"]
    administrator_login           = var.sql["administrator_login"]
    administrator_login_password  = local.administrator_login_password
    # ruleid: azure-mssql-service-mintls-version
    minimum_tls_version           = "1.0"
    public_network_access_enabled = var.sql["public_network_access_enabled"]
    identity {
    type = "SystemAssigned"
    }
}
```

**Correct (Azure MSSQL - TLS 1.2):**

```hcl
resource "azurerm_mssql_server" "examplea" {
    name                          = var.server_name
    resource_group_name           = var.resource_group.name
    location                      = var.resource_group.location
    version                       = var.sql["version"]
    administrator_login           = var.sql["administrator_login"]
    administrator_login_password  = local.administrator_login_password
    minimum_tls_version           = "1.2"
    public_network_access_enabled = var.sql["public_network_access_enabled"]
    identity {
    type = "SystemAssigned"
    }
}
```

**Incorrect (Azure SQL - wide-open firewall rule):**

```hcl
# ruleid: azure-sqlserver-no-public-access
resource "azurerm_mysql_firewall_rule" "example" {
  name                = "office"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mysql_server.example.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}
```

**Correct (Azure SQL - specific IP range):**

```hcl
resource "azurerm_mysql_firewall_rule" "example" {
  name                = "office"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mysql_server.example.name
  start_ip_address    = "40.112.8.12"
  end_ip_address      = "40.112.8.17"
}
```

**Incorrect (Azure MySQL - public network access enabled):**

```hcl
# ruleid: azure-mysql-public-access-disabled
resource "azurerm_mysql_server" "example" {
  name                = var.mysqlserver_name
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name

  administrator_login          = var.admin_name
  administrator_login_password = var.password
  sku_name = var.sku_name
  storage_mb = var.storage_mb
  version    = var.server_version

  auto_grow_enabled            = true
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  infrastructure_encryption_enabled = false
    public_network_access_enabled = true
}

# ruleid: azure-mysql-public-access-disabled
resource "azurerm_mysql_server" "example" {
  name                = var.mysqlserver_name
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name

  administrator_login          = var.admin_name
  administrator_login_password = var.password
  sku_name = var.sku_name
  storage_mb = var.storage_mb
  version    = var.server_version

  auto_grow_enabled            = true
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  infrastructure_encryption_enabled = false
}
```

**Correct (Azure MySQL - public network access disabled):**

```hcl
resource "azurerm_mysql_server" "example" {
  name                = var.mysqlserver_name
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name

  administrator_login          = var.admin_name
  administrator_login_password = var.password
  sku_name = var.sku_name
  storage_mb = var.storage_mb
  version    = var.server_version

  auto_grow_enabled            = true
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  infrastructure_encryption_enabled = false
  public_network_access_enabled = false
}
```

**Incorrect (Azure PostgreSQL - public network access enabled):**

```hcl
# ruleid: azure-postgresql-server-public-access-disabled
resource "azurerm_postgresql_server" "example" {
    name                = "example-psqlserver"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    administrator_login          = "psqladminun"
    administrator_login_password = "H@Sh1CoR3!"

    sku_name   = "GP_Gen5_4"
    version    = "9.6"
    storage_mb = 640000

    backup_retention_days        = 7
    geo_redundant_backup_enabled = true
    auto_grow_enabled            = true

    public_network_access_enabled    = true
    ssl_enforcement_enabled          = true
    ssl_minimal_tls_version_enforced = "TLS1_2"
}
```

**Correct (Azure PostgreSQL - public network access disabled):**

```hcl
resource "azurerm_postgresql_server" "example" {
    name                = "example-psqlserver"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    administrator_login          = "psqladminun"
    administrator_login_password = "H@Sh1CoR3!"

    sku_name   = "GP_Gen5_4"
    version    = "9.6"
    storage_mb = 640000

    backup_retention_days        = 7
    geo_redundant_backup_enabled = true
    auto_grow_enabled            = true

    public_network_access_enabled    = false
    ssl_enforcement_enabled          = true
    ssl_minimal_tls_version_enforced = "TLS1_2"
}
```

**Incorrect (Azure AKS - public cluster):**

```hcl
# ruleid: azure-aks-private-clusters-enabled
resource "azurerm_kubernetes_cluster" "example" {
name                = "example-aks1"
location            = azurerm_resource_group.example.location
resource_group_name = azurerm_resource_group.example.name
dns_prefix          = "exampleaks1"

    default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    }
    identity {
    type = "SystemAssigned"
    }
}

# ruleid: azure-aks-private-clusters-enabled
resource "azurerm_kubernetes_cluster" "example" {
    name                = "example-aks1"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    dns_prefix          = "exampleaks1"
    private_cluster_enabled = false

    default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    }

    identity {
    type = "SystemAssigned"
    }
}
```

**Correct (Azure AKS - private cluster enabled):**

```hcl
resource "azurerm_kubernetes_cluster" "example" {
name                = "example-aks1"
location            = azurerm_resource_group.example.location
resource_group_name = azurerm_resource_group.example.name
dns_prefix          = "exampleaks1"
private_cluster_enabled = true

default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
}

identity {
    type = "SystemAssigned"
}
}
```

**Incorrect (Azure AKS - no API server IP restrictions):**

```hcl
# ruleid: azure-aks-apiserver-auth-ip-ranges
resource "azurerm_kubernetes_cluster" "default" {
  name                = "example"
  location            = "azurerm_resource_group.example.location"
  resource_group_name = "azurerm_resource_group.example.name"
  dns_prefix          = "example"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}

# ruleid: azure-aks-apiserver-auth-ip-ranges
resource "azurerm_kubernetes_cluster" "empty" {
  name                = "example"
  location            = "azurerm_resource_group.example.location"
  resource_group_name = "azurerm_resource_group.example.name"
  dns_prefix          = "example"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  api_server_authorized_ip_ranges = []
}
```

**Correct (Azure AKS - authorized IP ranges configured):**

```hcl
resource "azurerm_kubernetes_cluster" "enabled" {
  name                = "example"
  location            = "azurerm_resource_group.example.location"
  resource_group_name = "azurerm_resource_group.example.name"
  dns_prefix          = "example"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  api_server_authorized_ip_ranges = ["192.168.0.0/16"]
}
```

**Incorrect (Azure AKS - no disk encryption set):**

```hcl
# ruleid: azure-aks-uses-disk-encryptionset
resource "azurerm_kubernetes_cluster" "example" {
    name                = "example-aks1"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    dns_prefix          = "exampleaks1"

    default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    }

    identity {
    type = "SystemAssigned"
    }
}
```

**Correct (Azure AKS - disk encryption set configured):**

```hcl
resource "azurerm_kubernetes_cluster" "example" {
    name                = "example-aks1"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    dns_prefix          = "exampleaks1"
    disk_encryption_set_id = "someId"

    default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    }

    identity {
    type = "SystemAssigned"
    }
}
```

**Incorrect (Azure Cosmos DB - public network access enabled):**

```hcl
# ruleid: azure-cosmosdb-disables-public-network
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    enable_automatic_failover = true

    consistency_policy {
    consistency_level       = "BoundedStaleness"
    max_interval_in_seconds = 10
    max_staleness_prefix    = 200
    }

    geo_location {
    location          = var.failover_location
    failover_priority = 1
    }

    geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
    }
}

# ruleid: azure-cosmosdb-disables-public-network
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    public_network_access_enabled = true
    enable_automatic_failover = true

    consistency_policy {
      consistency_level       = "BoundedStaleness"
      max_interval_in_seconds = 10
      max_staleness_prefix    = 200
    }

    geo_location {
      location          = var.failover_location
      failover_priority = 1
    }

    geo_location {
      location          = azurerm_resource_group.rg.location
      failover_priority = 0
    }
}
```

**Correct (Azure Cosmos DB - public network access disabled):**

```hcl
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    public_network_access_enabled = false
    enable_automatic_failover = true

    consistency_policy {
      consistency_level       = "BoundedStaleness"
      max_interval_in_seconds = 10
      max_staleness_prefix    = 200
    }

    geo_location {
      location          = var.failover_location
      failover_priority = 1
    }

    geo_location {
      location          = azurerm_resource_group.rg.location
      failover_priority = 0
    }

    key_vault_key_id = "A versionless Key Vault Key ID for CMK encryption"
}
```

**Incorrect (Azure Cosmos DB - no customer-managed key):**

```hcl
# ruleid: azure-cosmosdb-have-cmk
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    enable_automatic_failover = true

    consistency_policy {
    consistency_level       = "BoundedStaleness"
    max_interval_in_seconds = 10
    max_staleness_prefix    = 200
    }

    geo_location {
    location          = var.failover_location
    failover_priority = 1
    }

    geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
    }
}
```

**Correct (Azure Cosmos DB - customer-managed key configured):**

```hcl
resource "azurerm_cosmosdb_account" "db" {
    name                = "tfex-cosmos-db-${random_integer.ri.result}"
    location            = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name
    offer_type          = "Standard"
    kind                = "GlobalDocumentDB"

    enable_automatic_failover = true

    consistency_policy {
      consistency_level       = "BoundedStaleness"
      max_interval_in_seconds = 10
      max_staleness_prefix    = 200
    }

    geo_location {
      location          = var.failover_location
      failover_priority = 1
    }

    geo_location {
      location          = azurerm_resource_group.rg.location
      failover_priority = 0
    }

    key_vault_key_id = "A versionless Key Vault Key ID for CMK encryption"
}
```

**Incorrect (Azure Redis - non-SSL port enabled):**

```hcl
# ruleid: azure-redis-cache-enable-non-ssl-port
resource "azurerm_redis_cache" "example" {
    name                = "example-cache"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    capacity            = 2
    family              = "C"
    sku_name            = "Standard"
    enable_non_ssl_port = true
    minimum_tls_version = "1.2"
    public_network_access_enabled  = true
    redis_configuration {
    }
}
```

**Correct (Azure Redis - non-SSL port disabled):**

```hcl
resource "azurerm_redis_cache" "example" {
    name                = "example-cache"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    capacity            = 2
    family              = "C"
    sku_name            = "Standard"
    enable_non_ssl_port = false
    minimum_tls_version = "1.2"
    public_network_access_enabled  = true

    redis_configuration {
    }
}
```

**Incorrect (Azure VM Scale Set - encryption at host disabled):**

```hcl
# ruleid: azure-vmencryption-at-host-enabled
resource "azurerm_windows_virtual_machine_scale_set" "example" {
    name                = "example-vmss"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "Standard_F2"
    instances           = 1
    admin_password      = "P@55w0rd1234!"
    admin_username      = "adminuser"

    source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter-Server-Core"
    version   = "latest"
    }

    os_disk {
    storage_account_type = "Standard_LRS"
    caching              = "ReadWrite"
    }

    network_interface {
    name    = "example"
    primary = true

    ip_configuration {
        name      = "internal"
        primary   = true
        subnet_id = azurerm_subnet.internal.id
    }
    }
}

# ruleid: azure-vmencryption-at-host-enabled
resource "azurerm_linux_virtual_machine_scale_set" "example" {
    name                = "example-vmss"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "Standard_F2"
    instances           = 1
    admin_password      = "P@55w0rd1234!"
    admin_username      = "adminuser"
    encryption_at_host_enabled = false

    source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter-Server-Core"
    version   = "latest"
    }

    os_disk {
    storage_account_type = "Standard_LRS"
    caching              = "ReadWrite"
    }

    network_interface {
    name    = "example"
    primary = true

    ip_configuration {
        name      = "internal"
        primary   = true
        subnet_id = azurerm_subnet.internal.id
    }
    }
}
```

**Correct (Azure VM Scale Set - encryption at host enabled):**

```hcl
resource "azurerm_windows_virtual_machine_scale_set" "example" {
    name                = "example-vmss"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "Standard_F2"
    instances           = 1
    admin_password      = "P@55w0rd1234!"
    admin_username      = "adminuser"
    encryption_at_host_enabled = true

    source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter-Server-Core"
    version   = "latest"
    }

    os_disk {
    storage_account_type = "Standard_LRS"
    caching              = "ReadWrite"
    }

    network_interface {
    name    = "example"
    primary = true

    ip_configuration {
        name      = "internal"
        primary   = true
        subnet_id = azurerm_subnet.internal.id
    }
    }
}
```

**Incorrect (Azure Linux VM Scale Set - password authentication enabled):**

```hcl
# ruleid: azure-scale-set-password
resource "azurerm_linux_virtual_machine_scale_set" "example" {
    name                = var.scaleset_name
    resource_group_name = var.resource_group.name
    location            = var.resource_group.location
    sku                 = var.sku
    instances           = var.instance_count
    admin_username      = var.admin_username
    disable_password_authentication = false
    tags = var.common_tags
}
```

**Correct (Azure Linux VM Scale Set - SSH key authentication):**

```hcl
resource "azurerm_linux_virtual_machine_scale_set" "example" {
    name                = var.scaleset_name
    resource_group_name = var.resource_group.name
    location            = var.resource_group.location
    sku                 = var.sku
    instances           = var.instance_count
    admin_username      = var.admin_username
    disable_password_authentication = true

    admin_ssh_key {
        username   = var.admin_username
        public_key = tls_private_key.new.public_key_pem
    }
    tags = var.common_tags
}
```

**Incorrect (Azure Managed Disk - encryption disabled):**

```hcl
# ruleid: azure-managed-disk-encryption
resource "azurerm_managed_disk" "fail" {
  name                 = var.disk_name
  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_type = var.storage_account_type
  create_option        = "Empty"
  disk_size_gb         = var.disk_size_gb
  encryption_settings {
    enabled = false
  }
  tags = var.common_tags
}
```

**Correct (Azure Managed Disk - encryption enabled):**

```hcl
resource "azurerm_managed_disk" "pass2" {
  name                 = var.disk_name
  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_type = var.storage_account_type
  create_option        = "Empty"
  disk_size_gb         = var.disk_size_gb
  encryption_settings {
    enabled = true
  }
  tags = var.common_tags
}

resource "azurerm_managed_disk" "pass" {
  name                   = "acctestmd1"
  location               = "West US 2"
  resource_group_name    = azurerm_resource_group.example.name
  storage_account_type   = "Standard_LRS"
  create_option          = "Empty"
  disk_size_gb           = "1"
  disk_encryption_set_id = var.encryption_set_id

  tags = {
    environment = "staging"
  }
}
```

**Incorrect (Azure Container Group - no virtual network):**

```hcl
# ruleid: azure-containergroup-deployed-into-virtualnetwork
resource "azurerm_container_group" "example" {
    name                = "example-continst"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    ip_address_type     = "public"
    dns_name_label      = "aci-label"
    os_type             = "Linux"

    container {
    name   = "hello-world"
    image  = "microsoft/aci-helloworld:latest"
    cpu    = "0.5"
    memory = "1.5"

    ports {
        port     = 443
        protocol = "TCP"
    }
    }

    container {
    name   = "sidecar"
    image  = "microsoft/aci-tutorial-sidecar"
    cpu    = "0.5"
    memory = "1.5"
    }
}
```

**Correct (Azure Container Group - deployed into virtual network):**

```hcl
resource "azurerm_container_group" "example" {
    name                = "example-continst"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    ip_address_type     = "public"
    dns_name_label      = "aci-label"
    os_type             = "Linux"

    container {
    name   = "hello-world"
    image  = "microsoft/aci-helloworld:latest"
    cpu    = "0.5"
    memory = "1.5"

    ports {
        port     = 443
        protocol = "TCP"
    }
    }

    container {
    name   = "sidecar"
    image  = "microsoft/aci-tutorial-sidecar"
    cpu    = "0.5"
    memory = "1.5"
    }

    network_profile_id = "network_profile_id"
}
```

**Incorrect (Azure Data Factory - public network access enabled):**

```hcl
# ruleid: azure-datafactory-no-public-network-access
resource "azurerm_data_factory" "example" {
    name                = "example"
    location            = "azurerm_resource_group.example.location"
    resource_group_name = "azurerm_resource_group.example.name"
}

# ruleid: azure-datafactory-no-public-network-access
resource "azurerm_data_factory" "example" {
    name                = "example"
    location            = "azurerm_resource_group.example.location"
    resource_group_name = "azurerm_resource_group.example.name"
    public_network_enabled = true
}
```

**Correct (Azure Data Factory - public network access disabled):**

```hcl
resource "azurerm_data_factory" "example" {
    name                = "example"
    location            = "azurerm_resource_group.example.location"
    resource_group_name = "azurerm_resource_group.example.name"
    public_network_enabled = false
}
```

**Incorrect (Azure Data Lake Store - encryption disabled):**

```hcl
# ruleid: azure-datalake-store-encryption
resource "azurerm_data_lake_store" "example" {
    name                = "consumptiondatalake"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    encryption_state = "Disabled"
}

# ruleid: azure-datalake-store-encryption
resource "azurerm_data_lake_store" "example" {
    name                = "consumptiondatalake"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
}
```

**Correct (Azure Data Lake Store - encryption enabled):**

```hcl
resource "azurerm_data_lake_store" "example" {
    name                = "consumptiondatalake"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    encryption_state = "Enabled"
}
```

**Incorrect (Azure IoT Hub - public network access enabled):**

```hcl
# ruleid: azure-iot-no-public-network-access
resource "azurerm_iothub" "example" {
    name                = "Example-IoTHub"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location

    sku {
    name     = "S1"
    capacity = "1"
    }

    endpoint {
    type                       = "AzureIotHub.StorageContainer"
    connection_string          = azurerm_storage_account.example.primary_blob_connection_string
    name                       = "export"
    batch_frequency_in_seconds = 60
    max_chunk_size_in_bytes    = 10485760
    container_name             = azurerm_storage_container.example.name
    encoding                   = "Avro"
    file_name_format           = "{iothub}/{partition}_{YYYY}_{MM}_{DD}_{HH}_{mm}"
    }

    public_network_access_enabled = true
}
```

**Correct (Azure IoT Hub - public network access disabled):**

```hcl
resource "azurerm_iothub" "example" {
    name                = "Example-IoTHub"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location

    sku {
    name     = "S1"
    capacity = "1"
    }

    endpoint {
    type                       = "AzureIotHub.StorageContainer"
    connection_string          = azurerm_storage_account.example.primary_blob_connection_string
    name                       = "export"
    batch_frequency_in_seconds = 60
    max_chunk_size_in_bytes    = 10485760
    container_name             = azurerm_storage_container.example.name
    encoding                   = "Avro"
    file_name_format           = "{iothub}/{partition}_{YYYY}_{MM}_{DD}_{HH}_{mm}"
    }

    public_network_access_enabled = false
}
```

**Incorrect (Azure Event Grid - public network access enabled):**

```hcl
# ruleid: azure-eventgrid-domain-network-access
resource "azurerm_eventgrid_domain" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
}

# ruleid: azure-eventgrid-domain-network-access
resource "azurerm_eventgrid_domain" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    public_network_access_enabled = true
}
```

**Correct (Azure Event Grid - public network access disabled):**

```hcl
resource "azurerm_eventgrid_domain" "example" {
    name                = "example-app-service"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name

    public_network_access_enabled = false
}
```

**Incorrect (Azure Cognitive Services - public network access enabled):**

```hcl
# ruleid: azure-cognitiveservices-disables-public-network
resource "azurerm_cognitive_account" "examplea" {
  name                = "example-account"
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name
  kind                = "Face"
  public_network_access_enabled = true
  sku_name = "S0"
}

# ruleid: azure-cognitiveservices-disables-public-network
resource "azurerm_cognitive_account" "examplea" {
  name                = "example-account"
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name
  kind                = "Face"
  sku_name = "S0"
}
```

**Correct (Azure Cognitive Services - public network access disabled):**

```hcl
resource "azurerm_cognitive_account" "examplea" {
  name                = "example-account"
  location            = var.resource_group.location
  resource_group_name = var.resource_group.name
  kind                = "Face"
  public_network_access_enabled = false
  sku_name = "S0"
}
```

**Incorrect (Azure Search - public network access enabled):**

```hcl
# ruleid: azure-search-publicnetwork-access-disabled
resource "azurerm_search_service" "example" {
    name                = "example-search-service"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "standard"
    public_network_access_enabled = true
}

# ruleid: azure-search-publicnetwork-access-disabled
resource "azurerm_search_service" "example" {
    name                = "example-search-service"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "standard"
}
```

**Correct (Azure Search - public network access disabled):**

```hcl
resource "azurerm_search_service" "example" {
    name                = "example-search-service"
    resource_group_name = azurerm_resource_group.example.name
    location            = azurerm_resource_group.example.location
    sku                 = "standard"
    public_network_access_enabled = false
}
```

**Incorrect (Azure API Management - no virtual network):**

```hcl
# ruleid: azure-apiservices-use-virtualnetwork
resource "azurerm_api_management" "example" {
    name                = "example-apim"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    publisher_name      = "My Company"
    publisher_email     = "company@terraform.io"

    sku_name = "Developer_1"

    policy {
    xml_content = <<XML
    <policies>
        <inbound />
        <backend />
        <outbound />
        <on-error />
    </policies>
XML

    }
}
```

**Correct (Azure API Management - virtual network configured):**

```hcl
resource "azurerm_api_management" "example" {
    name                = "example-apim"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    publisher_name      = "My Company"
    publisher_email     = "company@terraform.io"

    sku_name = "Developer_1"
    virtual_network_configuration {
    subnet_id = azure_subnet.subnet_not_public_ip.id
    }
    policy {
    xml_content = <<XML
    <policies>
        <inbound />
        <backend />
        <outbound />
        <on-error />
    </policies>
XML

    }
}
```

**Incorrect (Azure IAM - custom role with wildcard actions):**

```hcl
resource "azurerm_role_definition" "example" {
    name        = "my-custom-role"
    scope       = data.azurerm_subscription.primary.id
    description = "This is a custom role created via Terraform"

    permissions {
    # ruleid: azure-customrole-definition-subscription-owner
    actions     = ["*"]
    not_actions = []
    }

    assignable_scopes = [
    data.azurerm_subscription.primary.id
    ]
}
```

**Correct (Azure IAM - custom role with specific permissions):**

```hcl
resource "azurerm_role_definition" "example" {
    name        = "my-custom-role"
    scope       = data.azurerm_subscription.primary.id
    description = "This is a custom role created via Terraform"

    permissions {
    actions     = [
    "Microsoft.Authorization/*/read",
        "Microsoft.Insights/alertRules/*",
        "Microsoft.Resources/deployments/write",
        "Microsoft.Resources/subscriptions/operationresults/read",
        "Microsoft.Resources/subscriptions/read",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Support/*"
        ]
    not_actions = []
    }

    assignable_scopes = [
    data.azurerm_subscription.primary.id
    ]
}
```
