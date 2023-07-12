package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.LinkedList;
import java.util.List;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class LogTemporaryCredentials extends MyScanner {
    public static final String ISSUE_NAME="Temporary AWS Credentials Found";
    public LogTemporaryCredentials(MontoyaApi api) {
        super(api);
    }

    @Override
    public List<AuditIssue> Scan(HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> auditIssues = new LinkedList<>();
        String target = CognitoShared.getXAmazonTarget(_api,baseRequestResponse);
        if(target!=null && !target.isEmpty() && target.equals("AWSCognitoIdentityService.GetCredentialsForIdentity") && baseRequestResponse.response().statusCode()==200) {
            AuditIssue auditIssue = auditIssue(ISSUE_NAME,
                    String.format("Temporary AWS Credentials Found from %s!",CognitoShared.getReferer(_api, baseRequestResponse.request())),
                    null,
                    baseRequestResponse.url(),
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.CERTAIN,
                    CognitoShared.EXPLOIT_DESCRIPTION,
                    null,
                    null,
                    baseRequestResponse);
            auditIssues.add(auditIssue);
        }
        return auditIssues;
    }
}
