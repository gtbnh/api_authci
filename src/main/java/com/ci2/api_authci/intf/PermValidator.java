package com.ci2.api_authci.intf;

import com.ci2.api_authci.util.MUtils;
import lombok.NonNull;
import org.springframework.web.method.HandlerMethod;

import java.util.List;

public interface PermValidator {

    default String getPerm(HandlerMethod handlerMethod){
        return MUtils.getHandlerMethodMethod(handlerMethod)+MUtils.concatHandlerMethodUri(handlerMethod);
    };

    default boolean isPermitted(String method,String uri, List<String> perms){
        if (perms==null || perms.size()==0) {
            return false;
        }
        for (String perm : perms) {
            if (isPermitted(method, uri, perm)) {
                return true;
            }
        }
        return false;
    };

    boolean isPermitted(String method,String uri, String perm);
}
