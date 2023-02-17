package com.tahu.thingsx.txserver.entity;


import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Data
@Document("tenant")
public class Tenant {

    @Id   //映射文档中的_id
    private String id;
    @Field
    private String name;
    @Field
    private String invitationCode;
    @Field
    private String userId;

}
