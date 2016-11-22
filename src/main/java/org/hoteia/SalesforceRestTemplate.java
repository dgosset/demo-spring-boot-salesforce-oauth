package org.hoteia;

import java.net.URI;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;

public class SalesforceRestTemplate extends OAuth2RestTemplate {

    private static final Logger log = LoggerFactory.getLogger(SalesforceRestTemplate.class);

	public SalesforceRestTemplate(OAuth2ProtectedResourceDetails resource) {
		super(resource);
	}
	
	public SalesforceRestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
		super(resource, context);
	}
	
	@Override
	public <T> T execute(String url, HttpMethod method, RequestCallback requestCallback,
			ResponseExtractor<T> responseExtractor, Map<String, ?> urlVariables) throws RestClientException {

		OAuth2AccessToken token = getAccessToken();
		Map<String, Object> additionalInformations = token.getAdditionalInformation();
		String newUserInformationUrl = (String) additionalInformations.get("id");
		
		URI expanded = getUriTemplateHandler().expand(newUserInformationUrl, urlVariables);
		return doExecute(expanded, method, requestCallback, responseExtractor);
	}

	@Override
	public <T> ResponseEntity<T> getForEntity(String url, Class<T> responseType, Object... urlVariables) throws RestClientException {
		
		OAuth2AccessToken token = getAccessToken();

		Map<String, Object> additionalInformations = token.getAdditionalInformation();
		log.info("AdditionalInformations : " + additionalInformations.toString());
		// Salesforce provides only sfdc_community_id, not a user_id. So we can't use this values in urlVariables and use the UrlBuilder with the uri pattern
		// like https://test.salesforce.com/id/{OMMUNITY_ID}/{USER_ID}/
		// We are forced to get the "id" value which is "THE" User URL, and replace the previous userInfoUri from application properties
		String newUserInformationUrl = (String)additionalInformations.get("id");
		
		RequestCallback requestCallback = acceptHeaderRequestCallback(responseType);
		ResponseExtractor<ResponseEntity<T>> responseExtractor = responseEntityExtractor(responseType);
		
		return execute(newUserInformationUrl, HttpMethod.GET, requestCallback, responseExtractor, urlVariables);
	}
	
}