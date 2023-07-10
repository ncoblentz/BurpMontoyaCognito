package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.nickcoblentz.montoya.utilities.LogHelper;

import java.util.List;

public class MyScanner {
    public final MontoyaApi _api;
    public LogHelper _loghelper;

    public MyScanner(MontoyaApi api)
    {
        _api = api;
        _loghelper=LogHelper.GetInstance(api);
    }

    public List<AuditIssue> Scan(HttpRequestResponse baseRequestResponse)
    {
        return null;
    }
}
