package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class IDPURLScanner extends MyScanner {

    public static String ISSUE_DETAIL ="<p>The following AWS Cognito IDP URL was accessed:</p><ul><li>%s</li></ul><p>From:</p><ul><li>%s</li></ul>";
    public static String ISSUE_NAME ="AWS Cognito IDP URL Found";
    public IDPURLScanner(MontoyaApi api)
    {
        super(api);
    }

    @Override
    public List<AuditIssue> Scan(HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> auditIssues = new LinkedList<>();
        if(CognitoShared.requestNotNull(baseRequestResponse)) {
            URL url = CognitoShared.getJavaURL(baseRequestResponse);
            _loghelper.Debug("Url: "+url.toString());
            if(url!=null) {
                if (CognitoShared.IDP_URL_PATTERN.matcher(url.getHost()).matches()) {
                    _loghelper.Debug("Matched");
                    String referer = CognitoShared.getReferer(_api, baseRequestResponse.request());

                    _loghelper.Debug("Referer: " + referer);

                    String detail = String.format(ISSUE_DETAIL, url, referer);

                    _loghelper.Debug("Detail: " + detail);

                    AuditIssue auditIssue = auditIssue(ISSUE_NAME,
                            detail,
                            null,
                            baseRequestResponse.request().url(),
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
