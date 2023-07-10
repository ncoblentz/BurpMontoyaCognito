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

public class LogIdTokenUserAttributesScanner extends MyScanner {
    public LogIdTokenUserAttributesScanner(MontoyaApi api)
    {
        super(api);
    }
    private static final String ISSUE_NAME = "AWS Cognito Custom User Attributes Found Through Logging In";
    @Override
    public List<AuditIssue> Scan(HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> auditIssues = new LinkedList<>();
        String target = CognitoShared.getXAmazonTarget(_api,baseRequestResponse);
        if(target!=null && !target.isEmpty() && (target.equals("AWSCognitoIdentityProviderService.RespondToAuthChallenge") || target.equals("AWSCognitoIdentityProviderService.InitiateAuth")) && baseRequestResponse.response().statusCode()==200)
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
                        JSONObject middleJson = new JSONObject(_api.utilities().base64Utils().decode(middle).toString());
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
        }
        return auditIssues;

    }
}
