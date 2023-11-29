package com.nickcoblentz.montoya.utilities;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;

import java.net.MalformedURLException;
import java.net.URL;


public class RequestHelper {
    private static String CombineNotes(String note1,String seperator, String note2)
    {
        if(note1==null || note1.length()<1){
            return note2;
        }
        if(note2==null || note1.length()<1){
            return note1;
        }
        return note1+seperator+note2;
    }
    public static void PrependNote(InterceptedRequest interceptedRequest, String note)
    {
        if(interceptedRequest!=null) {
            interceptedRequest.annotations().setNotes(CombineNotes(note,",",interceptedRequest.annotations().notes()));
        }
    }

    public static void AppendNote(InterceptedRequest interceptedRequest, String note)
    {
        if(interceptedRequest!=null) {
            interceptedRequest.annotations().setNotes(CombineNotes(interceptedRequest.annotations().notes(),",",note));
        }
    }

    public static void PrependNote(InterceptedTextMessage interceptedTextMessage, String note)
    {
        if(interceptedTextMessage!=null) {
            interceptedTextMessage.annotations().setNotes(CombineNotes(note,",",interceptedTextMessage.annotations().notes()));
        }
    }

    public static void AppendNote(InterceptedTextMessage interceptedTextMessage, String note)
    {
        if(interceptedTextMessage!=null) {
            interceptedTextMessage.annotations().setNotes(CombineNotes(interceptedTextMessage.annotations().notes(),",",note));
        }
    }

    public static String GetHeaderValue(HttpRequest request, String headerName)
    {
        if(request!=null && request.headers()!=null)
        {
            for(HttpHeader header : request.headers())
            {
                if(header.name().equalsIgnoreCase(headerName))
                {
                    return header.value();
                }
            }
        }
        return null;
    }

    public static String GetReferer(HttpRequest request)
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
        return getJavaURL(baseRequestResponse.request().url());
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
