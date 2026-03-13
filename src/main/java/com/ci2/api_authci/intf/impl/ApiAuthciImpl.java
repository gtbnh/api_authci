package com.ci2.api_authci.intf.impl;

import com.ci2.api_authci.intf.ApiAuthciIntf;


import java.util.List;


public class ApiAuthciImpl implements ApiAuthciIntf {


    @Override
    public List<String> getPermissions(Object loginId, String loginType) {
        return List.of();
    }
}
