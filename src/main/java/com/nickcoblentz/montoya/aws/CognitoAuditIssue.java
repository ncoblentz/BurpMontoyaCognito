package com.nickcoblentz.montoya.aws;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.nickcoblentz.montoya.utilities.RequestHelper;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class CognitoAuditIssue {
    public static String NAME_COGNITO_IDP_URL="AWS Cognito IDP URL Found";
    public static String DETAIL_COGNITO_IDP_URL="<p>The following AWS Cognito IDP URL was accessed:</p><ul><li>%s</li></ul><p>From:</p><ul><li>%s</li></ul>";

    public static Pattern IDP_URL_PATTERN=Pattern.compile("^cognito-idp(?:-fips)?.[^\\.]+.amazonaws.com$", Pattern.CASE_INSENSITIVE);
    public static String NAME_COGNITO_POOL_URL="AWS Cognito POOL URL Found";
    public static String DETAIL_COGNITO_POOL_URL="<p>The following AWS Cognito Pool URL was accessed:</p><ul><li>%s</li></ul><p>From:</p><ul><li>%s</li></ul>";
    public static Pattern POOL_URL_PATTERN=Pattern.compile("^cognito-identity(?:-fips)?.[^\\.]+.amazonaws.com$", Pattern.CASE_INSENSITIVE);

    public static AuditIssue PassiveCheckIDPURL(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        return PassiveCheckURL(api,baseRequestResponse,NAME_COGNITO_IDP_URL);
    }

    public static AuditIssue PassiveCheckPoolURL(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        return PassiveCheckURL(api,baseRequestResponse,NAME_COGNITO_POOL_URL);
    }

    public static AuditIssue PassiveCheckURL(MontoyaApi api, HttpRequestResponse baseRequestResponse,String issueName)
    {
        api.logging().logToOutput("PassiveCheckURL");
        if(baseRequestResponse!=null && baseRequestResponse.request()!=null) {
            URL url;
            try {
                url = new URL(baseRequestResponse.request().url());
            }
            catch(MalformedURLException e)
            {
                return null;
            }
            api.logging().logToOutput("Url: "+url.toString());

            Pattern selectedPattern;
            if(issueName.equals(NAME_COGNITO_IDP_URL))
            {
                selectedPattern=IDP_URL_PATTERN;
            }
            else if(issueName.equals(NAME_COGNITO_POOL_URL))
            {
                selectedPattern=POOL_URL_PATTERN;
            }
            else
            {
                return null;
            }
            api.logging().logToOutput("Pattern: "+selectedPattern);

            if(selectedPattern.matcher(url.getHost()).matches())
            {
                api.logging().logToOutput("Matched");
                String referer = RequestHelper.GetHeaderValue(baseRequestResponse.request(),"Referer");
                if(referer==null){
                    referer="none";
                }

                api.logging().logToOutput("Referer: "+referer);

                String detail="";
                if(issueName.equals(NAME_COGNITO_IDP_URL))
                {
                    detail=String.format(DETAIL_COGNITO_IDP_URL,url,referer);
                }
                else if(issueName.equals(NAME_COGNITO_POOL_URL))
                {
                    detail=String.format(DETAIL_COGNITO_POOL_URL,url,referer);
                }

                api.logging().logToOutput("Detail: "+detail);

                return auditIssue(issueName,
                        detail,
                        null,
                        referer,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        null,
                        null,
                        baseRequestResponse);
            }
        }
        return null;
    }


    public static List<AuditIssue> AllPassiveChecks(MontoyaApi api, HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> allIssues = new LinkedList<AuditIssue>();
        appendAuditIssue(allIssues,PassiveCheckIDPURL(api,baseRequestResponse));
        appendAuditIssue(allIssues,PassiveCheckPoolURL(api,baseRequestResponse));
        return allIssues;
    }

    public static void appendAuditIssue(List<AuditIssue> auditIssues, AuditIssue auditIssue)
    {
        if(auditIssue!=null)
        {
            auditIssues.add(auditIssue);
        }
    }
}
