package com.ci2.api_authci.intf;

import java.util.List;

/**
 *  API 鉴权接口
 *  API Authentication Interface
 * 
 *  该接口用于获取用户的权限列表，供拦截器进行权限验证
 *  This interface is used to get user permission list for interceptor to validate permissions
 */
public interface ApiAuthciIntf {

    /**
     * 获取用户权限列表
     * Get user permission list
     * 
     * @param loginId 登录id 可能为 null login id, may be null
     * @param loginType 登录类型 login type
     * @return 权限格式 method:uri permission format: method:uri
     * 例如 get:/user    post:/user    *:/user/**
     * For example: get:/user    post:/user    *:/user/**
     */
    List<String> getPermissions(Object loginId, String loginType);

}

