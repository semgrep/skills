---
title: Secure Kubernetes Configurations
impact: HIGH
---

## Secure Kubernetes Configurations

This guide provides security best practices for Kubernetes YAML configurations. Following these patterns helps prevent common security misconfigurations that could expose your containers and cluster to attacks.

Key Security Principles:
1. Least Privilege: Containers should run with minimal permissions and as non-root users
2. Isolation: Limit host namespace sharing (PID, network, IPC) to prevent container escapes
3. Immutability: Use read-only filesystems to prevent runtime modifications
4. Secure Communications: Always verify TLS certificates for encrypted connections
5. Secrets Management: Never store secrets directly in configuration files
6. RBAC: Apply principle of least privilege to cluster roles and permissions

**Incorrect (Pod - security context missing allowPrivilegeEscalation):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: allow-privilege-escalation-no-securitycontext
    - name: nginx
      image: nginx
```

**Incorrect (Pod - privilege escalation explicitly enabled):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: redis
      image: redis
      securityContext:
        # ruleid: allow-privilege-escalation-true
        allowPrivilegeEscalation: true
```

**Incorrect (Pod - security context exists but missing allowPrivilegeEscalation):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: postgres
      image: postgres
    # ruleid: allow-privilege-escalation
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
```

**Correct (Pod - privilege escalation explicitly disabled):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: allow-privilege-escalation
    - name: haproxy
      image: haproxy
      securityContext:
        allowPrivilegeEscalation: false
```

**Incorrect (Pod - no security context at pod level and no runAsNonRoot at container level):**

```yaml
apiVersion: v1
kind: Pod
# ruleid: run-as-non-root
spec:
  containers:
    - name: nginx
      image: nginx
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
```

**Incorrect (Pod - runAsNonRoot explicitly set to false at pod level):**

```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    # ruleid: run-as-non-root-unsafe-value
    runAsNonRoot: false
  containers:
    - name: redis
      image: redis
    - name: haproxy
      image: haproxy
```

**Incorrect (Pod - runAsNonRoot explicitly set to false at container level):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: redis
      image: redis
      securityContext:
        # ruleid: run-as-non-root-unsafe-value
        runAsNonRoot: false
```

**Incorrect (Pod - security context at pod level missing runAsNonRoot):**

```yaml
apiVersion: v1
kind: Pod
spec:
  # ruleid: run-as-non-root-security-context-pod-level
  securityContext:
    runAsGroup: 3000
  containers:
    - name: nginx
      image: nginx
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
```

**Incorrect (Pod - container security context missing runAsNonRoot when other containers have it):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # this is ok because there is no security context, requires different fix, so different rule
    # ok: run-as-non-root-container-level
    - name: nginx
      image: nginx
    - name: postgres
      image: postgres
      # ruleid: run-as-non-root-container-level
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
      # ok: run-as-non-root-container-level
      securityContext:
        runAsNonRoot: true
```

**Incorrect (Pod - container missing security context when other containers have runAsNonRoot):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: nginx
    # ruleid: run-as-non-root-container-level-missing-security-context
      image: nginx
    - name: postgres
      image: postgres
      # ok: run-as-non-root-container-level-missing-security-context
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
      # ok: run-as-non-root-container-level-missing-security-context
      securityContext:
        runAsNonRoot: true
```

**Correct (Pod - runAsNonRoot set at pod level):**

```yaml
apiVersion: v1
kind: Pod
spec:
  # ok: run-as-non-root
  securityContext:
    runAsNonRoot: true
  containers:
    - name: nginx
      image: nginx
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    - name: haproxy
      image: haproxy
```

**Correct (Pod - runAsNonRoot set at container level):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: haproxy
      image: haproxy
      securityContext:
        # ok: run-as-non-root-unsafe-value
        runAsNonRoot: true
```

**Incorrect (Pod - privileged mode at pod spec level):**

```yaml
apiVersion: v1
kind: Pod
spec:
  # ruleid: privileged-container
  privileged: true
  containers:
    - name: nginx
      image: nginx
```

**Incorrect (Pod - privileged mode at container level):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: privileged-container
    - name: nginx
      image: nginx
      securityContext:
        privileged: true
```

**Correct (Pod - privileged mode disabled):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: privileged-container
    - name: redis
      image: redis
      securityContext:
        privileged: false
```

**Correct (Pod - no privileged setting defaults to false):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: privileged-container
    - name: postgres
      image: postgres
```

**Incorrect (Pod - no readOnlyRootFilesystem setting):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: writable-filesystem-container
    - name: nginx
      image: nginx
```

**Incorrect (Pod - security context without readOnlyRootFilesystem):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: writable-filesystem-container
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
```

**Incorrect (Pod - readOnlyRootFilesystem explicitly set to false):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ruleid: writable-filesystem-container
    - name: redis
      image: redis
      securityContext:
        readOnlyRootFilesystem: false
```

**Correct (Pod - read-only root filesystem enabled):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: writable-filesystem-container
    - name: haproxy
      image: haproxy
      securityContext:
        readOnlyRootFilesystem: true
```

**Incorrect (Pod - seccomp profile set to unconfined):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: seccomp-confinement-disabled
    - name: nginx
      image: nginx
    # ok: seccomp-confinement-disabled
    - name: postgres
      image: postgres
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
    # ruleid: seccomp-confinement-disabled
    - name: redis
      image: redis
      securityContext:
        seccompProfile: unconfined
```

**Correct (Pod - no explicit seccomp disable uses default):**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # ok: seccomp-confinement-disabled
    - name: nginx
      image: nginx
      securityContext:
        runAsNonRoot: true
```

**Incorrect (Pod - host PID namespace enabled):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-pid
spec:
  # ruleid: hostpid-pod
  hostPID: true
  containers:
    - name: nginx
      image: nginx
```

**Correct (Pod - no hostPID setting defaults to false):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: nginx
      image: nginx
```

**Incorrect (Pod - host network namespace enabled):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-pid
spec:
  # ruleid: hostnetwork-pod
  hostNetwork: true
  containers:
    - name: nginx
      image: nginx
```

**Correct (Pod - no hostNetwork setting defaults to false):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: nginx
      image: nginx
```

**Incorrect (Pod - host IPC namespace enabled):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: view-pid
spec:
  # ruleid: hostipc-pod
  hostIPC: true
  containers:
    - name: nginx
      image: nginx
```

**Correct (Pod - no hostIPC setting defaults to false):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: nginx
      image: nginx
```

**Incorrect (Pod - Docker socket mounted as hostPath):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pd
spec:
  containers:
    - image: gcr.io/google_containers/test-webserver
      name: test-container
      volumeMounts:
        - mountPath: /var/run/docker.sock
          name: docker-sock-volume
  volumes:
    - name: docker-sock-volume
      # ruleid: exposing-docker-socket-hostpath
      hostPath:
        type: File
        path: /var/run/docker.sock
```

**Correct (Pod - no Docker socket mounting):**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pd
spec:
  containers:
    - image: gcr.io/google_containers/test-webserver
      name: test-container
      volumeMounts:
        - mountPath: /data
          name: data-volume
  volumes:
    - name: data-volume
      emptyDir: {}
```

**Incorrect (Secret - secrets stored in config file):**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  # ruleid: secrets-in-config-file
  USER NAME: Y2FsZWJraW5uZXk=
  # ok: secrets-in-config-file
  UUID: {UUID}
  # ruleid: secrets-in-config-file
  PASSWORD: UzNjcmV0UGEkJHcwcmQ=
  # ok: secrets-in-config-file
  SERVER: cHJvZA==
```

**Correct (Secret - use Sealed Secrets or external secrets management):**

```yaml
# Using Bitnami Sealed Secrets
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: mysecret
spec:
  encryptedData:
    password: AgBy8hCi8...encrypted...
```

**Incorrect (Config - TLS verification disabled for cluster):**

```yaml
apiVersion: v1
clusters:
  # ruleid: skip-tls-verify-cluster
  - cluster:
      server: https://192.168.0.100:8443
      insecure-skip-tls-verify: true
    name: minikube1
contexts:
  - context:
      cluster: minikube
      user: minikube
    name: minikube
current-context: minikube
kind: Config
```

**Correct (Config - TLS verification enabled):**

```yaml
apiVersion: v1
clusters:
  # ok: skip-tls-verify-cluster
  - cluster:
      server: https://192.168.0.101:8443
    name: minikube2
contexts:
  - context:
      cluster: minikube
      user: minikube
    name: minikube
current-context: minikube
kind: Config
users:
  - name: minikube
    user:
      client-certificate: client.crt
      client-key: client.key
```

**Incorrect (APIService - TLS verification disabled):**

```yaml
apiVersion: apiregistration.k8s.io/v1beta1
kind: APIService
metadata:
  name: v1beta1.metrics.k8s.io
# ruleid: skip-tls-verify-service
spec:
  service:
    name: metrics-server
    namespace: kube-system
  group: metrics.k8s.io
  version: v1beta1
  insecureSkipTLSVerify: true
  groupPriorityMinimum: 100
  versionPriority: 100
```

**Correct (APIService - TLS verification enabled):**

```yaml
apiVersion: apiregistration.k8s.io/v1beta1
kind: APIService
metadata:
  name: v1beta1.metrics.k8s.io
spec:
  service:
    name: metrics-server
    namespace: kube-system
  group: metrics.k8s.io
  version: v1beta1
  caBundle: <base64-encoded-ca-cert>
  groupPriorityMinimum: 100
  versionPriority: 100
```

**Incorrect (ClusterRole - wildcard permissions on core API):**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role
rules:
  # ok: legacy-api-clusterrole-excessive-permissions
  - apiGroups:
      - apps
    resources:
      - "*"
    verbs:
      - "*"
  - apiGroups:
      - ""
    resources:
  # ruleid: legacy-api-clusterrole-excessive-permissions
      - "*"
    verbs:
  # ruleid: legacy-api-clusterrole-excessive-permissions
      - "*"
```

**Incorrect (ClusterRole - inline wildcard permissions):**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role-inline
rules:
  - apiGroups: [""]
  # ruleid: legacy-api-clusterrole-excessive-permissions
    resources: ["*"]
  # ruleid: legacy-api-clusterrole-excessive-permissions
    verbs: ["*"]
```

**Correct (ClusterRole - explicit permissions):**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: good-role
rules:
  # ok: legacy-api-clusterrole-excessive-permissions
  - apiGroups:
      - ""
    resources:
      - configmaps
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
      - delete
```

**Correct (ClusterRole - wildcard resources but limited verbs):**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: read-only-role
rules:
  # ok: legacy-api-clusterrole-excessive-permissions
  - apiGroups:
      - ""
    resources: ["*"]
    verbs:
      - list
```

**Incorrect (Deployment - FLASK_ENV set to development):**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels:
    tags.datadoghq.com/env: dev
spec:
  template:
    metadata:
      labels:
        tags.datadoghq.com/env: dev
    spec:
      initContainers:
        - name: migrate-db
          env:
            - name: SQLALCHEMY_DATABASE_URI
              valueFrom:
                secretKeyRef:
                  name: backend-secrets
                  key: SQLALCHEMY_DATABASE_URI
                # ruleid: flask-debugging-enabled
            - name: FLASK_ENV
              value: development
```

**Correct (Deployment - FLASK_ENV set to non-development value):**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
spec:
  template:
    spec:
      containers:
        - name: backend
          env:
            # ok: flask-debugging-enabled
            - name: FLASK_ENV
              value: dev
```

**Incorrect (Deployment - fractional CPU limit causing throttling):**

```yaml
kind: Deployment
apiVersion: apps/v1
metadata:
  name: mumbledj
  namespace: mumble
spec:
  template:
    spec:
      containers:
        - name: app
          image: underyx/mumbledj
          resources:
            limits:
              # ruleid: no-fractional-cpu-limits
              cpu: 100m
              memory: 64Mi
            requests:
              # ok: no-fractional-cpu-limits
              cpu: 20m
              memory: 32Mi
```

**Correct (Deployment - full CPU unit limits):**

```yaml
kind: Deployment
apiVersion: apps/v1
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: panubo/sshd:1.1.0
          resources:
            limits:
              # ok: no-fractional-cpu-limits
              cpu: 1000m
              memory: 512Mi
            requests:
              cpu: 10m
              memory: 8Mi
```
