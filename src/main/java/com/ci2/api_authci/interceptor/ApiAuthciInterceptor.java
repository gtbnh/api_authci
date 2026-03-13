package com.ci2.api_authci.interceptor;

import com.ci2.api_authci.exception.PermDeniedException;
import com.ci2.api_authci.intf.ApiAuthciIntf;
import com.ci2.api_authci.property.ApiAuthciProperty;
import com.ci2.api_authci.util.AAUtil;
import com.ci2.api_authci.util.MUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.List;
import java.util.regex.Pattern;

@Component
public class ApiAuthciInterceptor implements HandlerInterceptor {

//    @Autowired
    private ApiAuthciProperty apiAuthciProperty;

//    @Autowired
    private ApiAuthciIntf apiAuthciIntf;

    public ApiAuthciInterceptor(ApiAuthciProperty apiAuthciProperty, ApiAuthciIntf apiAuthciIntf) {
        this.apiAuthciProperty = apiAuthciProperty;
        this.apiAuthciIntf = apiAuthciIntf;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
//        return HandlerInterceptor.super.preHandle(request, response, handler);

        if (!apiAuthciProperty.isEnabled()) {
            return true;
        }
//        String token = request.getHeader(apiTokenProperty.getHeaders().getToken());
//        if (MUtils.isBlank(token)) {
//            throw new PermDeniedException("token is empty");
//        }

        String method = request.getMethod();

        if ("options".equalsIgnoreCase(method)) {
            return true;
        }

        String uri = "";
        if (handler instanceof HandlerMethod) {

            uri = MUtils.concatHandlerMethodUri((HandlerMethod) handler);
        } else {

            uri = request.getRequestURI();
        }
//        List<String> publicResource = apiTokenProperty.getPublicResource();
//        for (int i = 0; i < publicResource.size(); i++) {
//            if (Pattern.matches(publicResource.get(i).replaceAll("/\\*\\*", ".*?"), uri)) {
//                return true;
//            }
//        }

        List<String> perms = apiAuthciIntf.getPermissions(AAUtil.tryGetLoginId(),
                AAUtil.tryGetLoginType());
        boolean hasPerm = false;
        if (perms != null) {
            for (int i = 0; i < perms.size(); i++) {
                String[] perm = perms.get(i).trim().split("[:：]");
                if (!"*".equals(perm[0]) && !method.equalsIgnoreCase(perm[0])) {
                    continue;
                }
                if (Pattern.matches(perm[1].replaceAll("/\\*\\*", ".*?"), uri)) {
                    hasPerm = true;
                    break;
                }
            }
        }

        if (!hasPerm) {
            throw new PermDeniedException();
        }


        return true;
    }



}
