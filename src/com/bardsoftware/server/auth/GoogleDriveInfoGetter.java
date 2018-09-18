// Copyright 2018 BarD Software s.r.o
package com.bardsoftware.server.auth;

import com.bardsoftware.server.AppCapabilitiesService;
import com.bardsoftware.server.AppUrlService;
import com.bardsoftware.server.HttpApi;
import org.json.JSONObject;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Same as EmailGetter, this servlet will run OAuth process similar to one that AuthServlet runs,
 * but with additional google drive scope. It assumes that user is already authenticated
 * with OAuth, and the only thing which is needed is to get his Drive scope.
 *
 * @author ed.zhavoronkov@gmail.com
 */
public class GoogleDriveInfoGetter extends AuthServlet {
  private static final Logger LOGGER = Logger.getLogger("GoogleDriveInfoGetter");

  public GoogleDriveInfoGetter(PrincipalExtent principalExtent, AppCapabilitiesService capabilities, AppUrlService urlService, Properties properties) {
    super(principalExtent, capabilities, urlService, properties);
  }

  // Basically we need access token and given name
  public JSONObject getGoogleDriveInfo(HttpApi http, String callback) throws IOException {
    try {
      Properties props = getProperties();
      final String googleDriveScope = props.getProperty("google.drive.scope");
      DefaultOAuthPlugin plugin = getOauthPlugin("google", props);
      if (plugin == null) {
        http.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return null;
      }

      plugin.setScope(googleDriveScope);
      ServiceBuilder serviceBuilder = new ServiceBuilder()
          .provider(plugin.getBuilderApiClass())
          .apiKey(plugin.getKey())
          .apiSecret(plugin.getSecret())
          .callback(callback)
          .scope(googleDriveScope);

      OAuthService service = serviceBuilder.build();

      return doOauthWithCallbackAndTokenHandler(http, plugin, service, token -> {
        OAuthRequest givenNameRequest = new OAuthRequest(Verb.GET, plugin.buildRequest(token.getRawResponse()));
        service.signRequest(token, givenNameRequest);
        JSONObject response = new JSONObject(givenNameRequest.send().getBody());
        String givenName = plugin.createUserName(response);

        return new JSONObject()
            .put(getProperties().getProperty("google.json.access_token"), token.getToken())
            .put(getProperties().getProperty("google.json.first_name"), givenName);
      });
    } catch (ClassNotFoundException e) {
      LOGGER.log(Level.SEVERE, "", e);
      http.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      return null;
    }
  }
}