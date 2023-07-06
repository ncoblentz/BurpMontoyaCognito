package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.nickcoblentz.montoya.utilities.RequestHelper;

public class AnnotateCognitoHandler implements ProxyRequestHandler {
    private final MontoyaApi _api;

    public AnnotateCognitoHandler(MontoyaApi api) {
        _api = api;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        handleRequest(interceptedRequest);
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    private void handleRequest(InterceptedRequest interceptedRequest)
    {
        if(interceptedRequest.url().toLowerCase().startsWith("https://cognito-"))
        {
            for(HttpHeader header : interceptedRequest.headers())
            {
                if(header.name().equalsIgnoreCase("X-Amz-Target"))
                {
                    RequestHelper.PrependNote(interceptedRequest,"Cognito: "+header.value());
                    break;
                }
            }
        }
    }
}
