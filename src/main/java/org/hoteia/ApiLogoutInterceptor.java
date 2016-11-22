package org.hoteia;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

public class ApiLogoutInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(ApiLogoutInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o) throws Exception {
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, ModelAndView modelAndView) throws Exception {
    	// We are using this interceptor to authorize b2b/b2c Rest call from the same internet browser.
    	// If we don't clear the security context, security keep the last user in cache
    	// So if we are logged as a b2c, call from b2b intranet are authenticated as a b2c.
    	// Don't use this way, if we have only one environnement for the API. (Save the perf)
    	// You can also split the API as 2 webapp, one b2c, one b2b with a different application.properties.
		SecurityContext securityContext = SecurityContextHolder.getContext();
		log.info("Interceptor Mvc, isAuthenticated  : " + securityContext.getAuthentication().isAuthenticated());
		if(securityContext.getAuthentication() != null 
				&& securityContext.getAuthentication().isAuthenticated()){
//			securityContext.setAuthentication(null);
			SecurityContextHolder.clearContext();
			log.info("Interceptor Mvc, clearContext");
		}
		HttpSession session = httpServletRequest.getSession(false);
		if(session != null){
		    session.invalidate();
			log.info("Interceptor Mvc, invalidate");
		}
    }

    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, Exception e) throws Exception {

    }
}

