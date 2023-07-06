package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
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
    private static final String NAME_COGNITO_CUSTOM_ATTRIBUTES_FOUND = "AWS Cognito Custom User Attributes Found";
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
        api.logging().logToOutput("PassiveCheckURL");
        if(baseRequestResponse!=null && baseRequestResponse.request()!=null) {
            URL url;
            try {
                url = new URL(baseRequestResponse.request().url());
            }
            catch(MalformedURLException e)
            {
                return null;
            }
            api.logging().logToOutput("Url: "+url.toString());

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
            api.logging().logToOutput("Pattern: "+selectedPattern);

            if(selectedPattern.matcher(url.getHost()).matches())
            {
                api.logging().logToOutput("Matched");
                String referer = RequestHelper.GetHeaderValue(baseRequestResponse.request(),"Referer");
                if(referer==null){
                    referer="none";
                }

                api.logging().logToOutput("Referer: "+referer);

                String detail="";
                if(issueName.equals(NAME_COGNITO_IDP_URL))
                {
                    detail=String.format(DETAIL_COGNITO_IDP_URL,url,referer);
                }
                else if(issueName.equals(NAME_COGNITO_POOL_URL))
                {
                    detail=String.format(DETAIL_COGNITO_POOL_URL,url,referer);
                }

                api.logging().logToOutput("Detail: "+detail);

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
        api.logging().logToOutput("PassiveCheckLogClientIDAndPools");
        if(baseRequestResponse!=null && baseRequestResponse.request()!=null) {
            URL url;
            try {
                url = new URL(baseRequestResponse.request().url());
            }
            catch(MalformedURLException e)
            {
                return null;
            }
            api.logging().logToOutput("Url: "+url.toString());




            if(GENERAL_URL_PATTERN.matcher(url.getHost()).matches())
            {
                List<AuditIssue> auditIssues = new LinkedList<>();
                Set<String> clientIDs = new HashSet<>();
                Set<String> identityPoolIDs = new HashSet<>();
                Set<String> userPoolIDs = new HashSet<>();
                api.logging().logToOutput("Matched");

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
                        api.logging().logToError("Found ClientID JSON but no or wrong value");
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
                        api.logging().logToError("Found IdentityPoolId JSON but no or wrong value");
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
                        api.logging().logToError("Found UserPoolId JSON but no or wrong value");
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
                    StringBuilder detailBuilder = new StringBuilder();
                    detailBuilder.append("<ul>");
                    for(String identityPoolID : identityPoolIDs)
                    {
                        detailBuilder.append(String.format("<li>%s (Referer: %s)</li>",identityPoolID,referer));
                    }
                    detailBuilder.append("</ul>");
                    AuditIssue clientIDAuditIssue = auditIssue(NAME_COGNITO_IDENTITY_POOL_ID,
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
        api.logging().logToOutput("PassiveCheckSuggestExploits");
        if(baseRequestResponse!=null && baseRequestResponse.request()!=null) {
            URL url;
            try {
                url = new URL(baseRequestResponse.request().url());
            }
            catch(MalformedURLException e)
            {
                return null;
            }
            api.logging().logToOutput("Url: "+url.toString());




            if(GENERAL_URL_PATTERN.matcher(url.getHost()).matches())
            {
                api.logging().logToOutput("Matched");
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
                                    api.logging().logToError("Found UserAttributes JSON but no or wrong value");
                                }
                                if(foundAttributes!=null) {
                                    for (int i = 0; i < foundAttributes.length(); i++) {
                                        Map<String,Object> attributeMap=null;
                                        try {
                                            attributeMap = foundAttributes.getJSONObject(i).toMap();
                                        }
                                        catch(JSONException e)
                                        {
                                            api.logging().logToError("Whoops that wasn't a map");
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
                                    AuditIssue auditIssue = auditIssue(NAME_COGNITO_CUSTOM_ATTRIBUTES_FOUND,
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
                        else if(header.value().equalsIgnoreCase("AWSCognitoIdentityProviderService.InitiateAuth"))
                        {
                            String details = String.format("Cognito Login request was made from %s",referer);
                            List<HttpRequestResponse> requestresponses = new LinkedList<>();
                            requestresponses.add(baseRequestResponse);
                            String body = baseRequestResponse.request().bodyToString();
                            if(body!=null && body.length()>0) {
                                JSONObject bodyJson = new JSONObject(body);
                                String clientId = null;
                                try {
                                    clientId = bodyJson.getString("ClientId");
                                } catch (JSONException e) {
                                    api.logging().logToError("Found ClientID JSON but no or wrong value");
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
