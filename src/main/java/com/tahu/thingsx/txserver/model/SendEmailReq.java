package com.tahu.thingsx.txserver.model;

import lombok.Data;

@Data
public class SendEmailReq {
    private String email;

    private String invitationCode;
}
