package com.tahu.thingsx.txserver.model;


import lombok.Data;

import java.util.List;

@Data
public class TenantAttributesReq {

    private String tenantId;

    private List<String> keys;
}
