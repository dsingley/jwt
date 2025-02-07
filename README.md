# jwt

- see https://jwt.io/
- uses https://github.com/auth0/java-jwt

#### parse a token on the command line
```bash
cat | jq -R 'split(".") | .[0:2] | map(@base64d) | map(fromjson)'
```
