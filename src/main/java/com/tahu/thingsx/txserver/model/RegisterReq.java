package com.tahu.thingsx.txserver.model;

import lombok.Data;

@Data
public class RegisterReq {

    private String email;

    private String invitationCode;
}
