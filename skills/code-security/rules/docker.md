---
title: Secure Docker Configurations
impact: HIGH
---

## Secure Docker Configurations

This guide provides security best practices for Dockerfiles and docker-compose configurations. Following these patterns helps prevent container escapes, privilege escalation, and other security vulnerabilities in containerized environments.

**Incorrect (Dockerfile - last user is root):**

The last user in the container should not be 'root'. If an attacker gains control of the container, they will have root access.

```dockerfile
FROM busybox

RUN git clone https://github.com/returntocorp/semgrep
RUN pip3 install semgrep
RUN semgrep -f p/xss
USER swuser
USER root

USER user1
# ruleid: last-user-is-root
USER root
```

**Correct (Dockerfile - last user is non-root):**

```dockerfile
FROM busybox

RUN git clone https://github.com/returntocorp/semgrep
RUN pip3 install semgrep
USER root
RUN apt-get update && apt-get install -y some-package
USER appuser
```

**Incorrect (Dockerfile - missing image version):**

Images should be tagged with an explicit version to produce deterministic container builds.

```dockerfile
# ruleid: missing-image-version
FROM debian

# ruleid: missing-image-version
FROM nixos/nix

# ruleid: missing-image-version
FROM debian AS blah

# ruleid: missing-image-version
FROM nixos/nix AS build

# ruleid: missing-image-version
FROM --platform=linux/amd64 debian

# ruleid: missing-image-version
FROM --platform=linux/amd64 debian as name
```

**Correct (Dockerfile - explicit image version):**

```dockerfile
# ok: missing-image-version
FROM debian:jessie

# ok: missing-image-version
FROM nixos/nix:2.7.0

# ok: missing-image-version
FROM debian:jessie AS blah

# ok: missing-image-version
FROM nixos/nix:2.7.0 AS build

# ok: missing-image-version
FROM --platform=linux/amd64 debian:jessie

# ok: missing-image-version
FROM --platform=linux/amd64 debian:jessie as name

# ok: missing-image-version
FROM python:3.10.1-alpine3.15@sha256:4be65b406f7402b5c4fd5df7173d2fd7ea3fdaa74d9c43b6ebd896197a45c448

# ok: missing-image-version
FROM python@sha256:4be65b406f7402b5c4fd5df7173d2fd7ea3fdaa74d9c43b6ebd896197a45c448

# ok: missing-image-version
FROM scratch
```

**Incorrect (Dockerfile - using latest tag):**

The 'latest' tag may change the base container without warning, producing non-deterministic builds.

```dockerfile
# ruleid: avoid-latest-version
FROM debian:latest

# ruleid: avoid-latest-version
FROM myregistry.local/testing/test-image:latest

# ruleid: avoid-latest-version
FROM debian:latest as blah

# ruleid: avoid-latest-version
FROM myregistry.local/testing/test-image:latest as blah
```

**Correct (Dockerfile - specific version tag):**

```dockerfile
# ok: avoid-latest-version
FROM debian:jessie

# ok: avoid-latest-version
FROM myregistry.local/testing/test-image:42ee222

# ok: avoid-latest-version
FROM debian:jessie as blah2

# ok: avoid-latest-version
FROM myregistry.local/testing/test-image:2a4af68 as blah2
```

**Incorrect (Dockerfile - relative WORKDIR):**

Use absolute paths for WORKDIR to prevent issues based on assumptions about the WORKDIR of previous containers.

```dockerfile
FROM busybox

# ruleid: use-absolute-workdir
WORKDIR usr/src/app

ENV dirpath=bar
# ruleid: use-absolute-workdir
WORKDIR ${dirpath}
```

**Correct (Dockerfile - absolute WORKDIR):**

```dockerfile
FROM busybox

# ok: use-absolute-workdir
WORKDIR /usr/src/app

ENV dirpath=/bar
# ok: use-absolute-workdir
WORKDIR ${dirpath}
```

**Incorrect (Dockerfile - using ADD for remote files):**

ADD will accept and include files from URLs and automatically extract archives. This potentially exposes the container to man-in-the-middle attacks. Use COPY instead for local files.

```dockerfile
FROM busybox

# ruleid: prefer-copy-over-add
ADD http://foo bar

# ruleid: prefer-copy-over-add
ADD https://foo bar

# ruleid: prefer-copy-over-add
ADD foo.tar.gz bar

# ruleid: prefer-copy-over-add
ADD foo.bz2 bar
```

**Correct (Dockerfile - using COPY or ADD for local files):**

```dockerfile
FROM busybox

# ok: prefer-copy-over-add
ADD foo bar

# ok: prefer-copy-over-add
ADD foo* /mydir/

# ok: prefer-copy-over-add
ADD hom?.txt /mydir/o

# ok: prefer-copy-over-add
ADD arr[[]0].txt /mydir/o

# ok: prefer-copy-over-add
ADD --chown=55:mygroup files* /somedir/

# ok: prefer-copy-over-add
ADD --chown=bin files* /somedir/
```

**Incorrect (Dockerfile - using RUN cd):**

Use 'WORKDIR' instead of 'RUN cd ...' for improved clarity and reliability. 'RUN cd ...' may not work as expected in a container.

```dockerfile
FROM busybox

# ruleid: use-workdir
RUN cd semgrep && git clone https://github.com/returntocorp/semgrep
```

**Correct (Dockerfile - using WORKDIR):**

```dockerfile
FROM busybox

# ok: use-workdir
RUN pip3 install semgrep && cd ..

# ok: use-workdir
RUN semgrep -f p/xss

# ok: use-workdir
RUN blah

# ok: use-workdir
RUN blah blahcd
```

**Incorrect (Dockerfile - using apt-get upgrade):**

Packages in base containers should be up-to-date, removing the need to upgrade or dist-upgrade. If a package is out of date, contact the maintainers.

```dockerfile
FROM debian

# ruleid:avoid-apt-get-upgrade
RUN apt-get update && apt-get upgrade

# ruleid:avoid-apt-get-upgrade
RUN apt-get update && apt-get upgrade -y

# ruleid:avoid-apt-get-upgrade
RUN apt-get update && apt-get dist-upgrade

# ruleid:avoid-apt-get-upgrade
RUN apt-get upgrade
```

**Correct (Dockerfile - only updating package lists):**

```dockerfile
FROM debian

# ok: avoid-apt-get-upgrade
RUN apt-get update
```

**Incorrect (Dockerfile - nonsensical commands):**

Some commands do not make sense in a container and should not be used. These include: shutdown, service, ps, free, top, kill, mount, ifconfig, nano, vim.

```dockerfile
FROM busybox

# ruleid: nonsensical-command
RUN top

# ruleid: nonsensical-command
RUN kill 1234

# ruleid: nonsensical-command
RUN ifconfig

# ruleid: nonsensical-command
RUN ps -ef

# ruleid: nonsensical-command
RUN vim /var/log/www/error.log
```

**Correct (Dockerfile - appropriate container commands):**

```dockerfile
FROM busybox

# ok: nonsensical-command
RUN git clone https://github.com/returntocorp/semgrep

# ok: nonsensical-command
RUN pip3 install semgrep

# ok: nonsensical-command
RUN semgrep -f p/xss
```

**Incorrect (Dockerfile - using --platform with FROM):**

Using '--platform' with FROM restricts the image to build on a single platform. Use 'docker buildx --platform=' instead for multi-platform builds.

```dockerfile
# ruleid: avoid-platform-with-from
FROM --platform=x86 busybox

# ruleid: avoid-platform-with-from
FROM --platform=x86 busybox:1.34

# ruleid: avoid-platform-with-from
FROM --platform=x86 busybox AS bb

# ruleid: avoid-platform-with-from
FROM --platform=x86 busybox:1.34 AS bb
```

**Correct (Dockerfile - FROM without platform restriction):**

```dockerfile
# ok: avoid-platform-with-from
FROM busybox

# ok: avoid-platform-with-from
FROM busybox:1.34

# ok: avoid-platform-with-from
FROM busybox AS bb

# ok: avoid-platform-with-from
FROM busybox:1.34 AS bb
```

**Incorrect (Docker Compose - privileged service):**

Running containers in privileged mode grants the container the equivalent of root capabilities on the host machine. This can lead to container escapes, privilege escalation, and other security concerns.

```yaml
version: "3.9"
services:
  # ok: privileged-service
  web:
    image: nginx:alpine
  worker:
    image: my-worker-image:latest
    # ruleid:privileged-service
    privileged: true
  # ok: privileged-service
  db:
    image: mysql
```

**Correct (Docker Compose - service without privileged mode):**

```yaml
version: "3.9"
services:
  web:
    image: nginx:alpine
  worker:
    image: my-worker-image:latest
    privileged: false
  db:
    image: mysql
```

**Incorrect (Docker Compose - writable filesystem):**

Services running with a writable root filesystem may allow malicious applications to download and run additional payloads, or modify container files. Use read-only filesystems when possible.

```yaml
version: "3.9"
services:
  # ruleid: writable-filesystem-service
  web:
    image: nginx:alpine
  # ruleid: writable-filesystem-service
  worker:
    image: my-worker-image:latest
    read_only: false
```

**Correct (Docker Compose - read-only filesystem):**

```yaml
version: "3.9"
services:
  # ok: writable-filesystem-service
  db:
    image: mysql
    read_only: true
```

**Incorrect (Docker Compose - exposing Docker socket):**

Exposing the host's Docker socket to containers via a volume is equivalent to giving unrestricted root access to your host. Never expose the Docker socket unless absolutely necessary.

```yaml
version: "3.9"
services:
  service02:
    image: my-worker-image:latest
    # ruleid: exposing-docker-socket-volume
    volumes:
      - /tmp/foo:/tmp/foo
      - /var/run/docker.sock:/var/run/docker.sock
  service05:
    image: ubuntu
    # ruleid: exposing-docker-socket-volume
    volumes:
      - /tmp/foo:/tmp/foo
      - /run/docker.sock:/run/docker.sock
  service14:
    image: redis:6
    # ruleid: exposing-docker-socket-volume
    volumes:
      - /var/run/docker.sock
  service22:
    image: debian:bullseye
    # ruleid: exposing-docker-socket-volume
    volumes:
      - source: /var/run/docker.sock
  service23:
    image: debian:buster
    # ruleid: exposing-docker-socket-volume
    volumes:
      - source: /var/run/docker.sock
        target: /var/run/docker.sock
```

**Correct (Docker Compose - no Docker socket exposure):**

```yaml
version: "3.9"
services:
  service01:
    image: nginx:alpine
    # ok: exposing-docker-socket-volume
    volumes:
      - /tmp/foo:/tmp/foo
      - /tmp/bar:/tmp/bar
  service28:
    image: mysql:latest
    # ok: exposing-docker-socket-volume
    volumes:
      - source: /tmp/foo
  service29:
    image: postgres:latest
    # ok: exposing-docker-socket-volume
    volumes:
      - source: /tmp/foo
        target: /tmp/bar
      - source: /tmp/bar
        target: /tmp/foo
```

**Incorrect (Python Docker SDK - arbitrary container run):**

If unverified user data can reach the `run` or `create` method, it can result in running arbitrary containers.

```python
import docker
client = docker.from_env()

def bad1(user_input):
    # ruleid: docker-arbitrary-container-run
    client.containers.run(user_input, 'echo hello world')

def bad2(user_input):
    # ruleid: docker-arbitrary-container-run
    client.containers.create(user_input, 'echo hello world')
```

**Correct (Python Docker SDK - hardcoded container image):**

```python
import docker
client = docker.from_env()

def ok1():
    # ok: docker-arbitrary-container-run
    client.containers.run("alpine", 'echo hello world')

def ok2():
    # ok: docker-arbitrary-container-run
    client.containers.create("alpine", 'echo hello world')
```
