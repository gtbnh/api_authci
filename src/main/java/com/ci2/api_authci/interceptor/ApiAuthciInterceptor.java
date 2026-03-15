package com.ci2.api_authci.interceptor;

import com.ci2.api_authci.exception.PermDeniedException;
import com.ci2.api_authci.intf.ApiAuthciIntf;
import com.ci2.api_authci.intf.PermValidator;
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

/**
 * API 鉴权拦截器
 * API Authentication Interceptor
 * 
 * 该拦截器用于拦截请求，根据用户权限判断是否允许访问
 * This interceptor is used to intercept requests and judge whether to allow access based on user permissions
 */
@Component
public class ApiAuthciInterceptor implements HandlerInterceptor {

    // 配置属性
    // Configuration properties
    private ApiAuthciProperty apiAuthciProperty;

    // 鉴权接口实现
    // Authentication interface implementation
    private ApiAuthciIntf apiAuthciIntf;

    private PermValidator permValidator;

    /**
     * 构造函数
     * Constructor
     * 
     * @param apiAuthciProperty 配置属性
     * @param apiAuthciProperty configuration properties
     * @param apiAuthciIntf 鉴权接口实现
     * @param apiAuthciIntf authentication interface implementation
     */
    public ApiAuthciInterceptor(ApiAuthciProperty apiAuthciProperty, ApiAuthciIntf apiAuthciIntf, PermValidator permValidator) {
        this.apiAuthciProperty = apiAuthciProperty;
        this.apiAuthciIntf = apiAuthciIntf;
        this.permValidator = permValidator;
    }

    /**
     * 请求处理前的拦截方法
     * Interception method before request processing
     * 
     * @param request HTTP请求
     * @param request HTTP request
     * @param response HTTP响应
     * @param response HTTP response
     * @param handler 处理器
     * @param handler handler
     * @return 是否允许请求继续执行
     * @return whether to allow the request to continue execution
     * @throws Exception 异常
     * @throws Exception exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 如果鉴权功能未启用，直接放行
        // If authentication is not enabled, directly allow
        if (!apiAuthciProperty.isEnabled()) {
            return true;
        }

        // 获取请求方法
        // Get request method
        String method = request.getMethod();

        // OPTIONS请求直接放行
        // OPTIONS request directly allowed
        if ("options".equalsIgnoreCase(method)) {
            return true;
        }

        // 获取请求URI
        // Get request URI
        String uri = "";
        if (handler instanceof HandlerMethod) {
            // 从HandlerMethod中获取URI
            // Get URI from HandlerMethod
            uri = MUtils.concatHandlerMethodUri((HandlerMethod) handler);
        } else {
            // 直接从请求中获取URI
            // Get URI directly from request
            uri = request.getRequestURI();
        }

        // 获取用户权限列表
        // Get user permission list
        List<String> perms = apiAuthciIntf.getPermissions(AAUtil.tryGetLoginId(),
                AAUtil.tryGetLoginType());
        
        // 判断是否有权限
        // Judge whether has permission
        boolean hasPerm = false;
        if (perms != null) {
            if (permValidator.isPermitted(method, uri, perms)) {
                hasPerm = true;
            }
        }

        // 没有权限，抛出异常
        // No permission, throw exception
        if (!hasPerm) {
            throw new PermDeniedException();
        }

        // 有权限，放行
        // Has permission, allow
        return true;
    }

}
