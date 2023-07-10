package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.*;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class LogGetUserUserAttributesScanner extends MyScanner {
    public LogGetUserUserAttributesScanner(MontoyaApi api)
    {
        super(api);
    }
    private static final String ISSUE_NAME = "AWS Cognito Custom User Attributes Found Through GetUser";
    @Override
    public List<AuditIssue> Scan(HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> auditIssues = new LinkedList<>();
        String target = CognitoShared.getXAmazonTarget(_api,baseRequestResponse);
        if(target!=null && !target.isEmpty())
        {
            String body = baseRequestResponse.response().bodyToString();
            if(body!=null && !body.isEmpty()) {
                JSONObject bodyJson = new JSONObject(body);
                Set<String> customUserAttributes = new HashSet<>();
                JSONArray foundAttributes=null;
                try {
                    foundAttributes = bodyJson.getJSONArray("UserAttributes");
                }
                catch(JSONException e)
                {
                    _loghelper.Error("Found UserAttributes JSON but no or wrong value");
                }
                if(foundAttributes!=null) {
                    for (int i = 0; i < foundAttributes.length(); i++) {
                        Map<String,Object> attributeMap=null;
                        try {
                            attributeMap = foundAttributes.getJSONObject(i).toMap();
                        }
                        catch(JSONException e)
                        {
                            _loghelper.Error("Whoops that wasn't a map");
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
                    builder.append(String.format("From: %s<br/>\n<ul>\n",CognitoShared.getReferer(_api,baseRequestResponse.request())));
                    for(String customAttribute : customUserAttributes)
                    {
                        builder.append(String.format("<li>%s</li>\n",customAttribute));
                    }
                    builder.append("</ul>");
                    AuditIssue auditIssue = auditIssue(ISSUE_NAME,
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
        return auditIssues;

    }
}
