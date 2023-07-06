package com.nickcoblentz.montoya.aws;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class MontoyaCognito implements BurpExtension {

    private MontoyaApi _api;
    private AnnotateCognitoHandler _handler;
    private CognitoPassiveScanChecks _scanchecks;


    @Override
    public void initialize(MontoyaApi api) {
        _api = api;
        _api.logging().logToOutput("Plugin Loading...");
        api.extension().setName("AWS Cognito");
        _scanchecks = new CognitoPassiveScanChecks(api);
        api.scanner().registerScanCheck(_scanchecks);
        _handler = new AnnotateCognitoHandler(api);
        api.proxy().registerRequestHandler(_handler);
        _api.logging().logToOutput("Plugin Loaded");
    }
}
