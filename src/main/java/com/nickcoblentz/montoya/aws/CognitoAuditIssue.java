package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.nickcoblentz.montoya.utilities.LogHelper;
import com.nickcoblentz.montoya.utilities.RequestHelper;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;


public class CognitoAuditIssue {
    public static final String NAME_COGNITO_CLIENT_ID = "AWS Cognito Client ID Found";
    private static final String NAME_COGNITO_IDENTITY_POOL_ID = "AWS Cognito Identity Pool ID Found";
    private static final String NAME_COGNITO_USER_POOL_ID = "AWS Cognito User Pool ID Found";
    private static final String NAME_COGNITO_SIGNUP_FOUND = "AWS Cognito Sign Up Request Found";
    private static final String BACKGROUND_COGNTIO_SIGNUP = """
Sign Up Requests accept custom parameters in the form of:
{
...
    "UserAttributes": [{
             "Name": "custom:user_type",
             "Value": "admin"
          },     \s          
          {
             "Name": "custom:tenant_id",
             "Value": "1"
          },
...
}""";
    private static final String NAME_COGNITO_AUTH_FOUND = "AWS Cognito Auth Found - Try Manual SignUp";
    private static final String BACKGROUND_COGNTIO_AUTH = "Try creating a user or updating a user's attributes (See the HTTP request tabs for examples) in applications that do not allow registration/signup and/or try custom fields for the signup."+BACKGROUND_COGNTIO_SIGNUP;
    private static final String NAME_COGNITO_CUSTOM_ATTRIBUTES_FOUND_GETUSER = "AWS Cognito Custom User Attributes Found Through GetUser";
    private static final String NAME_COGNITO_CUSTOM_ATTRIBUTES_FOUND_ID_TOKEN = "AWS Cognito Custom User Attributes Found Through Logging In";
    public static String NAME_COGNITO_IDP_URL="AWS Cognito IDP URL Found";
    public static String DETAIL_COGNITO_IDP_URL="<p>The following AWS Cognito IDP URL was accessed:</p><ul><li>%s</li></ul><p>From:</p><ul><li>%s</li></ul>";

    public static Pattern IDP_URL_PATTERN=Pattern.compile("^cognito-idp(?:-fips)?.[^\\.]+.amazonaws.com$", Pattern.CASE_INSENSITIVE);
    public static String NAME_COGNITO_POOL_URL="AWS Cognito POOL URL Found";
    public static String DETAIL_COGNITO_POOL_URL="<p>The following AWS Cognito Pool URL was accessed:</p><ul><li>%s</li></ul><p>From:</p><ul><li>%s</li></ul>";
    public static Pattern POOL_URL_PATTERN=Pattern.compile("^cognito-identity(?:-fips)?.[^\\.]+.amazonaws.com$", Pattern.CASE_INSENSITIVE);

    public static Pattern GENERAL_URL_PATTERN=Pattern.compile("^cognito-(?:identity|idp)(?:-fips)?.[^\\.]+.amazonaws.com$", Pattern.CASE_INSENSITIVE);

    public static AuditIssue PassiveCheckIDPURL(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        return PassiveCheckURL(api,baseRequestResponse,NAME_COGNITO_IDP_URL);
    }

    public static AuditIssue PassiveCheckPoolURL(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        return PassiveCheckURL(api,baseRequestResponse,NAME_COGNITO_POOL_URL);
    }

    public static AuditIssue PassiveCheckURL(MontoyaApi api, HttpRequestResponse baseRequestResponse,String issueName)
    {
        LogHelper loghelper = LogHelper.GetInstance(api);
        loghelper.Debug("PassiveCheckURL");
        if(baseRequestResponse!=null && baseRequestResponse.request()!=null) {
            URL url;
            try {
                url = new URL(baseRequestResponse.request().url());
            }
            catch(MalformedURLException e)
            {
                return null;
            }
            loghelper.Debug("Url: "+url.toString());

            Pattern selectedPattern;
            if(issueName.equals(NAME_COGNITO_IDP_URL))
            {
                selectedPattern=IDP_URL_PATTERN;
            }
            else if(issueName.equals(NAME_COGNITO_POOL_URL))
            {
                selectedPattern=POOL_URL_PATTERN;
            }
            else
            {
                return null;
            }
            loghelper.Debug("Pattern: "+selectedPattern);

            if(selectedPattern.matcher(url.getHost()).matches())
            {
                loghelper.Debug("Matched");
                String referer = RequestHelper.GetHeaderValue(baseRequestResponse.request(),"Referer");
                if(referer==null){
                    referer="none";
                }

                loghelper.Debug("Referer: "+referer);

                String detail="";
                if(issueName.equals(NAME_COGNITO_IDP_URL))
                {
                    detail=String.format(DETAIL_COGNITO_IDP_URL,url,referer);
                }
                else if(issueName.equals(NAME_COGNITO_POOL_URL))
                {
                    detail=String.format(DETAIL_COGNITO_POOL_URL,url,referer);
                }

                loghelper.Debug("Detail: "+detail);

                return auditIssue(issueName,
                        detail,
                        null,
                        baseRequestResponse.url(),
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        null,
                        null,
                        baseRequestResponse);
            }
        }
        return null;
    }

    public static List<AuditIssue> PassiveCheckLogClientIDAndPools(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        LogHelper loghelper = LogHelper.GetInstance(api);
        loghelper.Debug("PassiveCheckLogClientIDAndPools");
        if(baseRequestResponse!=null && baseRequestResponse.request()!=null) {
            URL url;
            try {
                url = new URL(baseRequestResponse.request().url());
            }
            catch(MalformedURLException e)
            {
                return null;
            }
            loghelper.Debug("Url: "+url.toString());




            if(GENERAL_URL_PATTERN.matcher(url.getHost()).matches())
            {
                List<AuditIssue> auditIssues = new LinkedList<>();
                Set<String> clientIDs = new HashSet<>();
                Set<String> identityPoolIDs = new HashSet<>();
                Set<String> userPoolIDs = new HashSet<>();
                loghelper.Debug("Matched");

                String referer = RequestHelper.GetHeaderValue(baseRequestResponse.request(),"Referer");
                if(referer==null){
                    referer="none";
                }

                for(ParsedHttpParameter parameter : baseRequestResponse.request().parameters())
                {
                    if(parameter.name().equalsIgnoreCase("ClientId"))
                    {
                        clientIDs.add(parameter.value());
                    }

                    if(parameter.name().equalsIgnoreCase("IdentityPoolId"))
                    {
                        identityPoolIDs.add(parameter.value());
                    }

                    if(parameter.name().equalsIgnoreCase("UserPoolId"))
                    {
                        userPoolIDs.add(parameter.value());
                    }
                }

                String body = baseRequestResponse.request().bodyToString();
                if(body!=null && body.length()>0) {
                    JSONObject bodyJson = new JSONObject(body);
                    String clientId = null;
                    try {
                        clientId = bodyJson.getString("ClientId");
                    }
                    catch(JSONException e)
                    {
                        loghelper.Error("Found ClientID JSON but no or wrong value");
                    }
                    if(clientId!=null && !clientId.trim().isEmpty())
                    {
                        clientIDs.add(clientId.trim());
                    }

                    String identityPoolId = null;
                    try {
                        clientId = bodyJson.getString("IdentityPoolId");
                    }
                    catch(JSONException e)
                    {
                        loghelper.Error("Found IdentityPoolId JSON but no or wrong value");
                    }
                    if(identityPoolId!=null && !identityPoolId.trim().isEmpty())
                    {
                        identityPoolIDs.add(identityPoolId.trim());
                    }

                    String userPoolId = null;
                    try {
                        userPoolId = bodyJson.getString("UserPoolId");
                    }
                    catch(JSONException e)
                    {
                        loghelper.Error("Found UserPoolId JSON but no or wrong value");
                    }
                    if(userPoolId!=null && !userPoolId.trim().isEmpty())
                    {
                        userPoolIDs.add(userPoolId.trim());
                    }

                }

                if(!clientIDs.isEmpty())
                {
                    StringBuilder detailBuilder = new StringBuilder();
                    detailBuilder.append("<ul>");
                    for(String clientId : clientIDs)
                    {
                        detailBuilder.append(String.format("<li>%s (Referer: %s)</li>",clientId,referer));
                    }
                    detailBuilder.append("</ul>");
                    AuditIssue clientIDAuditIssue = auditIssue(NAME_COGNITO_CLIENT_ID,
                            detailBuilder.toString(),
                            null,
                            baseRequestResponse.url(),
                            AuditIssueSeverity.INFORMATION,
                            AuditIssueConfidence.CERTAIN,
                            null,
                            null,
                            null,
                            baseRequestResponse);
                    auditIssues.add(clientIDAuditIssue);
                }
                if(!identityPoolIDs.isEmpty())
                {
                    List<HttpRequestResponse> requestResponses = new LinkedList<HttpRequestResponse>();
                    requestResponses.add(baseRequestResponse);
                    /*int start = baseRequestResponse.url().indexOf(".");
                    int end = baseRequestResponse.url().indexOf(".amazonaws.com");
                    String region=baseRequestResponse.url().substring(start,end-1);
                    HttpRequest baseIdentityRequest = HttpRequest.httpRequestFromUrl("https://cognito-identity."+region+".amazonaws.com/");*/
                    StringBuilder detailBuilder = new StringBuilder();
                    detailBuilder.append("<ul>");
                    for(String identityPoolID : identityPoolIDs)
                    {
                        detailBuilder.append(String.format("<li>%s (Referer: %s)</li>",identityPoolID,referer));
                        /*HttpRequest request1 = baseIdentityRequest.withAddedHeader("X-Amz-Target","AWSCognitoIdentityService.GetId");
                        request1.withBody(String.format("""
{"IdentityPoolId":"%s"}
                            """,identityPoolID));
                        requestResponses.add(HttpRequestResponse.httpRequestResponse(request1,null));*/
                    }
                    detailBuilder.append("</ul>");
                    AuditIssue clientIDAuditIssue = auditIssue(NAME_COGNITO_IDENTITY_POOL_ID,
                            detailBuilder.toString(),
                            null,
                            baseRequestResponse.url(),
                            AuditIssueSeverity.INFORMATION,
                            AuditIssueConfidence.CERTAIN,
                            """
                                    <p>Try:</p>
                                    <ul>
                                    <li>omit regions with:<code>export AWS_DEFAULT_REGION="regionhere"</code>. Otherwise include <code>--region regionhere</code></li>
                                    <li><code>export AWS_IDENTITY_POOL_ID="identitypoolidhere"</code>. Otherwise include <code>--region regionhere</code></li>
                                    <li><code>aws cognito-identity get-id --identity-pool-id $AWS_IDENTITY_POOL_ID </code></li>
                                    <li>Produces an IdentityId (use below): <code>aws cognito-identity get-id --identity-pool-id $AWS_IDENTITY_POOL_ID --logins cognito-idp.$AWS_DEFAULT_REGION.amazonaws.com/issuerfromidtokenhere=idtokenvaluehere</code></li>
                                    <li><code>export AWS_IDENTITY_ID="valuefromabove"</code>
                                    <li>Produces SessionToken, SecretKey, SecretKey: <code>aws cognito-identity get-credentials-for-identity --identity-id $AWS_IDENTITY_ID --logins cognito-idp.$AWS_DEFAULT_REGION.amazonaws.com/issuerfromidtokenhere=idtokenvalueherefrominitauthresponse</code></li>
                                    <li>Set Values:<code>export AWS_ACCESS_KEY_ID=...'export AWS_SECRET_ACCESS_KEY=...;export AWS_SESSION_TOKEN=...</li>
                                    <li><code>aws sts get-caller-identity #check which roles this identity has</code></li>
                                    <li><code>aws cognito-identity describe-identity --identity-id $AWS_IDENTITY_ID</code></li>
                                    <li><code>aws cognito-identity describe-identity-pool --identity-pool-id $AWS_IDENTITY_POOL_ID</code></li>
                                    <li><code>aws cognito-identity list-identity-pools --max-results 100</code></li>
                                    <li><code>aws cognito-identity list-identities --identity-pool-id $AWS_IDENTITY_POOL_ID --max-results 100</code></li>
                                    <li><code>aws cognito-idp list-users --user-pool-id $AWS_IDENTITY_POOL_ID</code></li>
                                    <li><code>aws cognito-idp admin-list-devices --username test1 --user-pool-id $AWS_IDENTITY_POOL_ID</code></li>
                                    <li>Basic Flow Enabled? <code>aws cognito-identity get-open-id-token --identity-id $AWS_IDENTITY_ID --no-sign</code> and <code>aws sts assume-role-with-web-identity --role-arn <role_arn> --role-session-name sessionname --web-identity-token <token> --no-sign</code></li>
                                    <li><code>git clone https://github.com/andresriancho/enumerate-iam.git</code>, also see https://github.com/andresriancho/enumerate-iam/pull/15/commits/77ad5b41216e3b5f1511d0c385da8cd5984c2d3c to prevent it from getting stuck, then <code>./enumerate-iam.py --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY --session-token $AWS_SESSION_TOKEN --region $AWS_DEFAULT_REGION</code>          
                                    </ul>
                                    <p>Reference: https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_Operations.html</p>
                                                                """,
                            null,
                            null,
                            baseRequestResponse);
                    auditIssues.add(clientIDAuditIssue);
                }

                if(!userPoolIDs.isEmpty())
                {
                    StringBuilder detailBuilder = new StringBuilder();
                    detailBuilder.append("<ul>");
                    for(String userPoolID : userPoolIDs)
                    {
                        detailBuilder.append(String.format("<li>%s (Referer: %s)</li>",userPoolID,referer));
                    }
                    detailBuilder.append("</ul>");
                    AuditIssue clientIDAuditIssue = auditIssue(NAME_COGNITO_USER_POOL_ID,
                            detailBuilder.toString(),
                            null,
                            baseRequestResponse.url(),
                            AuditIssueSeverity.INFORMATION,
                            AuditIssueConfidence.CERTAIN,
                            null,
                            null,
                            null,
                            baseRequestResponse);
                    auditIssues.add(clientIDAuditIssue);
                }
                return auditIssues;
            }
        }
        return null;
    }

    private static List<AuditIssue> PassiveCheckSuggestExploits(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        LogHelper loghelper = LogHelper.GetInstance(api);
        loghelper.Debug("PassiveCheckSuggestExploits");
        if(baseRequestResponse!=null && baseRequestResponse.request()!=null) {
            URL url;
            try {
                url = new URL(baseRequestResponse.request().url());
            }
            catch(MalformedURLException e)
            {
                return null;
            }
            loghelper.Debug("Url: "+url.toString());




            if(GENERAL_URL_PATTERN.matcher(url.getHost()).matches())
            {
                loghelper.Debug("Matched");
                List<AuditIssue> auditIssues = new LinkedList<>();

                String referer = RequestHelper.GetHeaderValue(baseRequestResponse.request(),"Referer");
                if(referer==null){
                    referer="none";
                }

                for(HttpHeader header : baseRequestResponse.request().headers())
                {
                    if(header.name().equalsIgnoreCase("X-Amz-Target"))
                    {
                        if(header.value().equals("AWSCognitoIdentityProviderService.SignUp"))
                        {
                            String details = String.format("Cognito Sign Up request was made from %s",referer);

                            AuditIssue signUpAuditIssue = auditIssue(NAME_COGNITO_SIGNUP_FOUND,
                                    details,
                                    null,
                                    baseRequestResponse.url(),
                                    AuditIssueSeverity.INFORMATION,
                                    AuditIssueConfidence.CERTAIN,
                                    BACKGROUND_COGNTIO_SIGNUP,
                                    null,
                                    null,
                                    baseRequestResponse);
                            auditIssues.add(signUpAuditIssue);
                        }
                        else if(header.value().equals("AWSCognitoIdentityProviderService.GetUser"))
                        {
                            String body = baseRequestResponse.response().bodyToString();
                            if(body!=null && body.length()>0) {
                                JSONObject bodyJson = new JSONObject(body);
                                Set<String> customUserAttributes = new HashSet<>();
                                JSONArray foundAttributes=null;
                                try {
                                    foundAttributes = bodyJson.getJSONArray("UserAttributes");
                                }
                                catch(JSONException e)
                                {
                                    loghelper.Error("Found UserAttributes JSON but no or wrong value");
                                }
                                if(foundAttributes!=null) {
                                    for (int i = 0; i < foundAttributes.length(); i++) {
                                        Map<String,Object> attributeMap=null;
                                        try {
                                            attributeMap = foundAttributes.getJSONObject(i).toMap();
                                        }
                                        catch(JSONException e)
                                        {
                                            loghelper.Error("Whoops that wasn't a map");
                                        }
                                        if (attributeMap!=null && attributeMap.get("Name").toString().startsWith("custom:"))
                                        {
                                            customUserAttributes.add(attributeMap.get("Name").toString());
                                        }
                                    }
                                }
                                if(!customUserAttributes.isEmpty())
                                {
                                    StringBuilder builder = new StringBuilder();
                                    builder.append(String.format("From: %s<br/>\n<ul>\n",referer));
                                    for(String customAttribute : customUserAttributes)
                                    {
                                        builder.append(String.format("<li>%s</li>\n",customAttribute));
                                    }
                                    builder.append("</ul>");
                                    AuditIssue auditIssue = auditIssue(NAME_COGNITO_CUSTOM_ATTRIBUTES_FOUND_GETUSER,
                                            builder.toString(),
                                            null,
                                            baseRequestResponse.url(),
                                            AuditIssueSeverity.INFORMATION,
                                            AuditIssueConfidence.CERTAIN,
                                            null,
                                            null,
                                            null,
                                            baseRequestResponse);
                                    auditIssues.add(auditIssue);
                                }
                            }
                        }
                        else if(header.value().equalsIgnoreCase("AWSCognitoIdentityProviderService.RespondToAuthChallenge"))
                        {
                            CheckCustomAttributesInAccessToken(api,baseRequestResponse,auditIssues);
                        }
                        else if(header.value().equalsIgnoreCase("AWSCognitoIdentityProviderService.InitiateAuth"))
                        {
                            String details = String.format("Cognito Login request was made from %s",referer);
                            CheckCustomAttributesInAccessToken(api,baseRequestResponse,auditIssues);
                            List<HttpRequestResponse> requestresponses = new LinkedList<>();
                            requestresponses.add(baseRequestResponse);
                            String body = baseRequestResponse.request().bodyToString();
                            if(body!=null && body.length()>0) {
                                JSONObject bodyJson = new JSONObject(body);
                                String clientId = null;
                                try {
                                    clientId = bodyJson.getString("ClientId");
                                } catch (JSONException e) {
                                    loghelper.Error("Found ClientID JSON but no or wrong value");
                                }
                                if (clientId != null && !clientId.trim().isEmpty()) {
                                    HttpRequest requestSignUp = baseRequestResponse.request().withRemovedHeader("X-Amz-Target");
                                    HttpRequest requestUpdateAttribute = baseRequestResponse.request().withRemovedHeader("X-Amz-Target");
                                    requestSignUp = requestSignUp.withAddedHeader("X-Amz-Target","AWSCognitoIdentityProviderService.SignUp");
                                    requestUpdateAttribute = requestUpdateAttribute.withAddedHeader("X-Amz-Target","AWSCognitoIdentityProviderService.UpdateUserAttributes");
                                    requestSignUp = requestSignUp.withBody(String.format(
"""
//https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html <-- Delete Me
{
   "ClientId": "%s",
   "Password": "YourPasswordHere",
   "UserAttributes": [{
         "Name": "custom:customfieldhere",
         "Value": "ValueHere"
      },     
      {
         "Name": "email",
         "Value": "me@somethinghere.com"
      }
   ],
   "Username": "YourUsernameHere"
}
        """,clientId));
                                    requestresponses.add(HttpRequestResponse.httpRequestResponse(requestSignUp,null));

                                    requestUpdateAttribute = requestUpdateAttribute.withBody(String.format(
                                            """
//https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html <-- Delete Me
//https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html <-- Delete Me
{
   "AccessToken": "AccessTokenFromUserLoginHere",
   "UserAttributes": [
     {
        "Name": "custom:customfieldhere",
        "Value": "ValueHere"
     }
  ]
}
                                                                                                        """));
                                    requestresponses.add(HttpRequestResponse.httpRequestResponse(requestUpdateAttribute,null));
                                }
                            }

                            AuditIssue auditIssue = auditIssue(NAME_COGNITO_AUTH_FOUND,
                                    details,
                                    null,
                                    baseRequestResponse.url(),
                                    AuditIssueSeverity.INFORMATION,
                                    AuditIssueConfidence.CERTAIN,
                                    BACKGROUND_COGNTIO_AUTH,
                                    null,
                                    null,
                                    requestresponses);
                            auditIssues.add(auditIssue);
                        }
                        break;
                    }
                }
                return auditIssues;
            }
        }
        return null;
    }

    private static void CheckCustomAttributesInAccessToken(MontoyaApi api, HttpRequestResponse baseRequestResponse, List<AuditIssue> auditIssues) {
        if(baseRequestResponse.response().statusCode()==200)
        {
            String body = baseRequestResponse.response().bodyToString();
            if(body!=null && !body.isEmpty())
            {
                JSONObject bodyJSON = new JSONObject(body);
                if(bodyJSON.has("AuthenticationResult") && bodyJSON.getJSONObject("AuthenticationResult").has("IdToken"))
                {
                    String idToken = bodyJSON.getJSONObject("AuthenticationResult").getString("IdToken");
                    if(idToken!=null && !idToken.isEmpty())
                    {
                        int start = idToken.indexOf(".");
                        int end = idToken.indexOf(".",start+1);
                        String middle=idToken.substring(start+1,end);
                        JSONObject middleJson = new JSONObject(api.utilities().base64Utils().decode(middle).toString());
                        Set<String> customAttributesSet = new HashSet<>();
                        for (Map.Entry<String, Object> entry : middleJson.toMap().entrySet()) {
                            if(entry.getKey().startsWith("custom:"))
                            {
                                customAttributesSet.add(entry.getKey());
                            }
                        }
                        StringBuilder builder = new StringBuilder();
                        builder.append("<ul>");
                        for(String attribute : customAttributesSet)
                        {
                            builder.append(String.format("<li>%s</li>",attribute));
                        }
                        builder.append("</ul>");
                        AuditIssue auditIssue = auditIssue(NAME_COGNITO_CUSTOM_ATTRIBUTES_FOUND_ID_TOKEN,
                                builder.toString(),
                                null,
                                baseRequestResponse.url(),
                                AuditIssueSeverity.INFORMATION,
                                AuditIssueConfidence.CERTAIN,
                                null,
                                null,
                                null,
                                baseRequestResponse);
                        auditIssues.add(auditIssue);

                    }
                }
            }
        }

    }

    public static List<AuditIssue> AllPassiveChecks(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> allIssues = new LinkedList<AuditIssue>();
        appendAuditIssue(allIssues,PassiveCheckIDPURL(api,baseRequestResponse));
        appendAuditIssue(allIssues,PassiveCheckPoolURL(api,baseRequestResponse));
        appendAuditIssue(allIssues,PassiveCheckLogClientIDAndPools(api,baseRequestResponse));
        appendAuditIssue(allIssues,PassiveCheckSuggestExploits(api,baseRequestResponse));
        return allIssues;
    }



    public static void appendAuditIssue(List<AuditIssue> auditIssues, AuditIssue auditIssue)
    {
        if(auditIssue!=null)
        {
            auditIssues.add(auditIssue);
        }
    }

    public static void appendAuditIssue(List<AuditIssue> existingAuditIssues, List<AuditIssue> newAuditIssues)
    {
        if(newAuditIssues!=null && !newAuditIssues.isEmpty())
        {
            existingAuditIssues.addAll(newAuditIssues);
        }
    }
}
