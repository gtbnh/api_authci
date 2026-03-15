package com.ci2.api_authci.intf.impl;

import com.ci2.api_authci.intf.PermValidator;
import com.ci2.api_authci.util.MUtils;
import org.springframework.web.method.HandlerMethod;

import java.util.List;
import java.util.regex.Pattern;

public class ApiPermValidator implements PermValidator {


    @Override
    public boolean isPermitted(String method,String uri, String perm) {
        // 解析权限字符串，格式为 method:uri
        // Parse permission string, format: method:uri
        if ("*:/**".equals(perm)){
            return true;
        }
        if (MUtils.isBlank(perm)) {
            return false;
        }

        String[] ps = perm.trim().split("[:：]");

        // 检查请求方法是否匹配
        // Check if request method matches
        if (!"*".equals(ps[0]) && !method.equalsIgnoreCase(ps[0])) {
            return false;
        }

        // 检查URI是否匹配
        // Check if URI matches
        return Pattern.matches(ps[1].replaceAll("/\\*\\*", ".*?"), uri);
    }
}
