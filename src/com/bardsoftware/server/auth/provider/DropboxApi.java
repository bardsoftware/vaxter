// Copyright (C) 2018 BarD Software
package com.bardsoftware.server.auth.provider;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConfig;
import org.scribe.utils.OAuthEncoder;

/**
 * @author edzhavoronkov@gmail.com
 */
public class DropboxApi extends DefaultApi20 {
  private static final String AUTHORIZE_URL = "https://www.dropbox.com/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=code";
  private static final String ACCESS_TOKEN_ENDPOINT = "https://api.dropboxapi.com/oauth2/token";

  public DropboxApi() {
  }

  @Override
  public String getAccessTokenEndpoint() {
    return ACCESS_TOKEN_ENDPOINT;
  }

  @Override
  public String getAuthorizationUrl(OAuthConfig config) {
    return String.format(AUTHORIZE_URL, config.getApiKey(), OAuthEncoder.encode(config.getCallback()));
  }
}
