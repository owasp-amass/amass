# [![OWASP Logo](../../images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/)

This example uses Docker Compose (with support for version 3 schemas) to setup an environment with JanusGraph, Scylla/Cassandra and Elasticsearch.

## Installation

If you're running this on a laptop, these servers require a large amount of the system resources. In some cases, OWASP Amass testers needed to give Docker 8 cores, 16GB of memory, and at least 10GB of disk image size.

It is recommended that you copy this directory to another location outside the git repo that can also provide plenty of storage for the servers.

From this directory, execute the following command:

```bash
docker-compose up --build
```

If this is the first time you started up the environment, then you need to run the initialization script as follows:

```bash
docker-compose exec janus ./bin/gremlin.sh -e /workspace/janusgraph/scripts/amass-init.groovy
```

## Thanks

* The [janusgraph-docker](https://github.com/sunsided/janusgraph-docker/) repo, by [Markus Mayer](https://github.com/sunsided), made this much easier for the OWASP Amass Project.
