package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;

public class CognitoPassiveScanChecks implements ScanCheck {

    private final MontoyaApi _api;

    public CognitoPassiveScanChecks(MontoyaApi api) {
        _api = api;
    }


    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return auditResult();
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        _api.logging().logToOutput("Passive hit");
        List<AuditIssue> auditIssues = CognitoAuditIssue.AllPassiveChecks(_api,baseRequestResponse);
        return auditResult(auditIssues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        //if(newIssue.name().equals(CognitoAuditIssue.NAME_COGNITO_IDP_URL) || newIssue.name().equals(CognitoAuditIssue.NAME_COGNITO_POOL_URL) || newIssue.name().equals(CognitoAuditIssue.NAME_COGNITO_CLIENT_ID))
        //{
            return existingIssue.detail().equals(newIssue.detail()) ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
        //}
        //return ConsolidationAction.KEEP_BOTH;
    }
}
