package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URL;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class ClientPoolIdentityIDScanner extends MyScanner {

    public static final String NAME_COGNITO_CLIENT_ID = "AWS Cognito Client ID Found";
    private static final String NAME_COGNITO_IDENTITY_POOL_ID = "AWS Cognito Identity Pool ID Found";
    private static final String NAME_COGNITO_USER_POOL_ID = "AWS Cognito User Pool ID Found";
    public ClientPoolIdentityIDScanner(MontoyaApi api)
    {
        super(api);
    }

    @Override
    public List<AuditIssue> Scan(HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> auditIssues = new LinkedList<>();
        if(CognitoShared.requestNotNull(baseRequestResponse)) {
            URL url = CognitoShared.getJavaURL(baseRequestResponse);
            _loghelper.Debug("Url: " + url.toString());
            if (url != null) {
                if (CognitoShared.GENERAL_URL_PATTERN.matcher(url.getHost()).matches()) {
                    Set<String> clientIDs = new HashSet<>();
                    Set<String> identityPoolIDs = new HashSet<>();
                    Set<String> userPoolIDs = new HashSet<>();
                    _loghelper.Debug("Matched");
                    String referer = CognitoShared.getReferer(_api, baseRequestResponse.request());

                    _loghelper.Debug("Referer: " + referer);

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
                            _loghelper.Error("Found ClientID JSON but no or wrong value");
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
                            _loghelper.Error("Found IdentityPoolId JSON but no or wrong value");
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
                            _loghelper.Error("Found UserPoolId JSON but no or wrong value");
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
                                CognitoShared.EXPLOIT_DESCRIPTION,
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
                }
            }
        }
        return auditIssues;
    }

}
