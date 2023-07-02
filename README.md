# jwt

- see https://jwt.io/
- uses https://github.com/auth0/java-jwt

#### parse a token on the command line
```bash
cat | jq -R 'split(".") | .[0:2] | map(@base64d) | map(fromjson)'
```

#### run zookeeper in docker
```bash
docker run \
  --rm \
  --name zookeeper \
  -e JVMFLAGS='-Dzookeeper.extendedTypesEnabled=true' \
  -p 2181:2181 \
  zookeeper
```

#### zookeeper command line
```bash
docker exec -it zookeeper bin/zkCli.sh
```
