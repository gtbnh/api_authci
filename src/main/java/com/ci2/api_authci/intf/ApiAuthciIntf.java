package com.ci2.api_authci.intf;

import java.util.List;

public interface ApiAuthciIntf {

    /**
     *
     * @param loginId 登录id 可能为 null
     * @param loginType 登录类型
     * @return 权限格式 method:uri
     * 例如 get:/user    post:/user    *:/user/**
     */
    List<String> getPermissions(Object loginId,String loginType);




}
