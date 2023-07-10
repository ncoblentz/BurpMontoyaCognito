package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.nickcoblentz.montoya.utilities.LogHelper;

import java.util.LinkedList;
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
        LogHelper loghelper = LogHelper.GetInstance(_api);
        loghelper.Debug("Passive hit");
        List<AuditIssue> auditIssues = new LinkedList<>();
        List<MyScanner> scanners = new LinkedList<>();
        scanners.add(new IDPURLScanner(_api));
        scanners.add(new PoolURLScanner(_api));
        scanners.add(new ClientPoolIdentityIDScanner(_api));
        scanners.add(new LogGetUserUserAttributesScanner(_api));
        scanners.add(new LogIdTokenUserAttributesScanner(_api));
        scanners.add(new SuggestExploitsScanner(_api));

        for(MyScanner scanner : scanners)
        {
            auditIssues.addAll(scanner.Scan(baseRequestResponse));
        }

        //CognitoAuditIssue.AllPassiveChecks(_api,baseRequestResponse);
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
