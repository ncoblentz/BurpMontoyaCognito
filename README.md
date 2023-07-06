# Burp AWS Cognito (Using the Montoya API)
__Author: Nick Coblentz__

This extension helps identify key information from requests to AWS Cognito and provides templates for exploiting several known vulnerabilities. Features include:
- Proxy History: Adding comments to Burp Proxy History to reflect the Cognito Method found in `X-Amz-Target: AWSCognitoIdentityProviderService.RevokeToken`
- Passive Scan Issues:
  - Log URLs observed matching `^cognito-(?:identity|idp)(?:-fips)?.[^\.]+.amazonaws.com$`
  - Log Identity Pool IDs observed in requests
  - Log Client IDs observed in requests
  - Log custom user attributes found in the `idToken` or `GetUser` response
  - Log `InitiateAuth` requests and suggest request templates for `SignUp` and `UpdateUserAttributes` 

## How to Download this Plugin
Check out the "packages" section on the right of this GitHub Repo

## How to build this plugin
### Command-Line
```bash
$ ./gradlew fatJar
```
### InteliJ
1. Open the project in Intellij
2. Open the Gradle sidebar on the right hand side
3. Choose Tasks -> Other -> fatJar

## How to add this plugin to Burp
1. Open Burp Suite
2. Go to Extensions -> Installed -> Add
    - Extension Type: Java
    - Extension file: build/libs/burpmontoyacognito-1.0-SNAPSHOT-fatjar.jar
