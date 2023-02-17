package com.tahu.thingsx.txserver.controller;


import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.UpdateResult;
import com.tahu.thingsx.txserver.entity.Tenant;
import com.tahu.thingsx.txserver.entity.UserAdmin;
import com.tahu.thingsx.txserver.util.ResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Slf4j
@Controller
@RequestMapping("/thingsX")
public class MongoController {
    @Autowired
    MongoTemplate mongoTemplate;


    @RequestMapping("/tenants")
    @ResponseBody
    public Object getAllTenant() {
        List<Tenant> tenants = mongoTemplate.findAll(Tenant.class);
        log.info("mongo all tenants,{}", tenants);
        return ResponseUtil.ok(tenants);
    }

    @RequestMapping("/insert/tenant")
    @ResponseBody
    public Object insertTenant(@RequestBody Tenant tenant) {
        Tenant t = mongoTemplate.insert(tenant);
        log.info("mongo insert tenant,{}", t);
        return ResponseUtil.ok();
    }

    @RequestMapping("/update/tenant")
    @ResponseBody
    public Object updateTenant(@RequestBody Tenant tenant) {
        Query query = new Query(Criteria.where("name").is(tenant.getName()));


        List<Tenant> tenants = mongoTemplate.find(query, Tenant.class);
        log.info("mongo update tenant before {}", tenants);
        Update update = new Update();
        //设置更新属性
        update.set("name",tenant.getName());
        update.set("ivitationCode", tenant.getInvitationCode());
        update.set("userId", tenant.getUserId());
        UpdateResult updateResult = mongoTemplate.upsert(query, update, Tenant.class);


        log.info("mongo update tenant counts :{}", updateResult.getModifiedCount());
        return ResponseUtil.ok(updateResult.getModifiedCount());
    }


    @RequestMapping("/delete/tenant")
    @ResponseBody
    public Object deleteTenant(@RequestBody Tenant tenant) {
        Query query = new Query(Criteria.where("name").is(tenant.getName()));

        List<Tenant> tenants = mongoTemplate.find(query, Tenant.class);
        log.info("mongo delete tenant before {}", tenants);

        DeleteResult deleteResult = mongoTemplate.remove(query, Tenant.class);


        log.info("mongo delete tenant counts :{}", deleteResult.getDeletedCount());
        return ResponseUtil.ok(deleteResult.getDeletedCount());
    }



    @RequestMapping("/userAdmins")
    @ResponseBody
    public Object getAllUserAdmin() {
        List<UserAdmin> userAdmins = mongoTemplate.findAll(UserAdmin.class);
        log.info("mongo all userAdmin,{}", userAdmins);
        return ResponseUtil.ok(userAdmins);
    }

    @RequestMapping("/insert/userAdmin")
    @ResponseBody
    public Object insertUserAdmin(@RequestBody UserAdmin userAdmin) {
        UserAdmin t = mongoTemplate.insert(userAdmin);
        log.info("mongo insert userAdmin,{}", t);
        return ResponseUtil.ok();
    }

    @RequestMapping("/update/userAdmin")
    @ResponseBody
    public Object updateUserAdmin(@RequestBody UserAdmin userAdmin) {
        Query query = new Query(Criteria.where("name").is(userAdmin.getName()));
        List<UserAdmin> userAdmins = mongoTemplate.find(query, UserAdmin.class);
        log.info("mongo update userAdmin before {}", userAdmins);
        Update update = new Update();
        //设置更新属性
        update.set("name", userAdmin.getName());
        update.set("passWord", userAdmin.getPassWord());
        update.set("role", userAdmin.getRole());
        update.set("userId", userAdmin.getUserId());
        UpdateResult updateResult = mongoTemplate.upsert(query, update, UserAdmin.class);


        log.info("mongo update userAdmin counts :{}", updateResult.getModifiedCount());
        return ResponseUtil.ok(updateResult.getModifiedCount());
    }


    @RequestMapping("/delete/userAdmin")
    @ResponseBody
    public Object deleteUserAdmin(@RequestBody UserAdmin userAdmin) {
        Query query = new Query(Criteria.where("name").is(userAdmin.getName()));

        List<UserAdmin> tenants = mongoTemplate.find(query, UserAdmin.class);
        log.info("mongo delete userAdmin before {}", tenants);

        DeleteResult deleteResult = mongoTemplate.remove(query, UserAdmin.class);


        log.info("mongo delete userAdmin counts :{}", deleteResult.getDeletedCount());
        return ResponseUtil.ok(deleteResult.getDeletedCount());
    }
}
