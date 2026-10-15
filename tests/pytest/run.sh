#!/bin/bash

# also works: alias docker='podman'

docker container rm -f test_db 2>/dev/null || true
docker network rm -f test_net 2>/dev/null || true

set -e

docker build --pull -t testrunner -f ./Dockerfile ../..

docker network create test_net

docker run -dt -e POSTGRES_PASSWORD=secret --name test_db --net test_net docker.io/postgres:16-alpine

sleep 5

docker run -t --rm --name test_runner --net test_net -e db_dsn=postgresql://postgres:secret@test_db/postgres -v $PWD/coverage:/runner/htmlcov testrunner
