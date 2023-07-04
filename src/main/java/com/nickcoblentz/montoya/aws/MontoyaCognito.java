package com.nickcoblentz.montoya.aws;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class MontoyaCognito implements BurpExtension {

    private MontoyaApi _api;
    private AnnotateCognitoHandler handler;


    @Override
    public void initialize(MontoyaApi api) {
        _api = api;
        _api.logging().logToOutput("Plugin Loading...");
        api.extension().setName("AWS Cognito");
        handler = new AnnotateCognitoHandler(api);
        api.proxy().registerRequestHandler(handler);
        _api.logging().logToOutput("Plugin Loaded");
    }
}
