package com.tahu.thingsx.txserver.entity;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Data
@Document("userAdmin")
public class UserAdmin {

    @Id
    private String id;

    @Field
    private String name;

    @Field
    private String passWord;

    @Field
    private String role;

    @Field
    private String userId;
}
