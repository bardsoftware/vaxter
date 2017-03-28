// Copyright (C) 2017 BarD Software
package com.bardsoftware.server.auth.provider;

import org.scribe.builder.api.FacebookApi;
import org.scribe.extractors.AccessTokenExtractor;

/**
 * @author dbarashev@bardsoftware.com
 */
public class FacebookCustomApi extends FacebookApi {
  @Override
  public AccessTokenExtractor getAccessTokenExtractor() {
    return new JsonAccessTokenExtractor();
  }
}
