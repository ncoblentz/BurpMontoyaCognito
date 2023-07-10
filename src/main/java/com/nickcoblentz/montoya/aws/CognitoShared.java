package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.nickcoblentz.montoya.utilities.LogHelper;
import com.nickcoblentz.montoya.utilities.RequestHelper;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.regex.Pattern;

public class CognitoShared {

    public static final Pattern IDP_URL_PATTERN=Pattern.compile("^cognito-idp(?:-fips)?.[^\\.]+.amazonaws.com$", Pattern.CASE_INSENSITIVE);
    public static final Pattern POOL_URL_PATTERN=Pattern.compile("^cognito-identity(?:-fips)?.[^\\.]+.amazonaws.com$", Pattern.CASE_INSENSITIVE);

    public static final Pattern GENERAL_URL_PATTERN=Pattern.compile("^cognito-(?:identity|idp)(?:-fips)?.[^\\.]+.amazonaws.com$", Pattern.CASE_INSENSITIVE);

    public static final String X_AMAZON_TARGET="X-Amz-Target";

    public static String getReferer(MontoyaApi api, HttpRequest request)
    {
        String referer = "";
        if(requestNotNull(request)) {
            if (request != null) {
                referer = RequestHelper.GetHeaderValue(request, "Referer");
                if (referer == null) {
                    referer = "";
                }
            }
        }
        return referer;
    }

    public static String getXAmazonTarget(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        if(requestNotNull(baseRequestResponse))
        {
            String target = RequestHelper.GetHeaderValue(baseRequestResponse.request(), X_AMAZON_TARGET);
            return target;
        }
        return null;

    }

    public static boolean requestNotNull(HttpRequestResponse baseRequestResponse)
    {
        return baseRequestResponse!=null && baseRequestResponse!=null;
    }

    public static boolean requestNotNull(HttpRequest request)
    {
        return request!=null;
    }

    public static boolean responseNotNull(HttpResponse response)
    {
        return response!=null;
    }

    public static boolean responseNotNull(HttpRequestResponse baseRequestResponse)
    {
        return baseRequestResponse!=null && baseRequestResponse.response()!=null;
    }

    public static URL getJavaURL(HttpRequestResponse baseRequestResponse)
    {
        return getJavaURL(baseRequestResponse.url());
    }

    public static URL getJavaURL(HttpRequest request)
    {
        return getJavaURL(request.url());
    }

    public static URL getJavaURL(String urlString)
    {
        URL url=null;
        try
        {
            url = new URL(urlString);
        }
        catch(MalformedURLException e)
        {
            url=null;
        }
        return url;
    }
}
