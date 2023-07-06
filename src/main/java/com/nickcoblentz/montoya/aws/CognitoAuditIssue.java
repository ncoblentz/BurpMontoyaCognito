package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.nickcoblentz.montoya.utilities.RequestHelper;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class CognitoAuditIssue {
    public static final String NAME_COGNITO_CLIENT_ID = "AWS Cognito Client ID Found";
    private static final String NAME_COGNITO_POOL_ID = "AWS Cognito Identity POOL ID Found";
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
                api.logging().logToOutput("Matched");

                String referer = RequestHelper.GetHeaderValue(baseRequestResponse.request(),"Referer");
                if(referer==null){
                    referer="none";
                }

                for(ParsedHttpParameter parameter : baseRequestResponse.request().parameters())
                {
                    if(parameter.name().equalsIgnoreCase("ClientId"))
                    {
                        clientIDs.add(String.format("<li>%s (Referer: %s)</li>",parameter.value(),api.utilities().htmlUtils().encode(referer)));
                    }

                    if(parameter.name().equalsIgnoreCase("IdentityPoolId"))
                    {
                        identityPoolIDs.add(String.format("<li>%s (Referer: %s)</li>",parameter.value(),api.utilities().htmlUtils().encode(referer)));
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

                }

                if(clientIDs.size()>0)
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
                if(identityPoolIDs.size()>0)
                {
                    StringBuilder detailBuilder = new StringBuilder();
                    detailBuilder.append("<ul>");
                    for(String identityPoolID : identityPoolIDs)
                    {
                        detailBuilder.append(String.format("<li>%s (Referer: %s)</li>",identityPoolID,referer));
                    }
                    detailBuilder.append("</ul>");
                    AuditIssue clientIDAuditIssue = auditIssue(NAME_COGNITO_POOL_ID,
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


    public static List<AuditIssue> AllPassiveChecks(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> allIssues = new LinkedList<AuditIssue>();
        appendAuditIssue(allIssues,PassiveCheckIDPURL(api,baseRequestResponse));
        appendAuditIssue(allIssues,PassiveCheckPoolURL(api,baseRequestResponse));
        appendAuditIssue(allIssues,PassiveCheckLogClientIDAndPools(api,baseRequestResponse));
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
        if(newAuditIssues!=null && newAuditIssues.size()>0)
        {
            existingAuditIssues.addAll(newAuditIssues);
        }
    }
}
