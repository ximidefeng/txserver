package com.tahu.thingsx.txserver.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.tahu.thingsx.txserver.config.TXRestClient;
import com.tahu.thingsx.txserver.config.ThingsBoardRestClientConfig;
import com.tahu.thingsx.txserver.entity.Tenant;
import com.tahu.thingsx.txserver.entity.UserAdmin;
import com.tahu.thingsx.txserver.model.RegisterReq;
import com.tahu.thingsx.txserver.model.SendEmailReq;
import com.tahu.thingsx.txserver.model.TenantAttributesReq;
import com.tahu.thingsx.txserver.util.ResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.thingsboard.server.common.data.Customer;
import org.thingsboard.server.common.data.EntityType;
import org.thingsboard.server.common.data.User;
import org.thingsboard.server.common.data.id.EntityId;
import org.thingsboard.server.common.data.id.UserId;
import org.thingsboard.server.common.data.kv.AttributeKvEntry;
import org.thingsboard.server.common.data.security.Authority;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Controller
@RequestMapping("/thingsX/tx")
public class ThingsBoardController {

    @Autowired
    private TXRestClient restClient;

    @Autowired
    private ThingsBoardRestClientConfig thingsBoardRestClientConfig;

    @Autowired
    MongoTemplate mongoTemplate;

    @Autowired
    MessageSource messageSource;

    @RequestMapping("/register")
    @ResponseBody
    public Object register(HttpServletRequest request, @RequestBody RegisterReq registerReq) {
        // ?????????????????????  ?????????????????????????????????
        // ?????????????????? ??????
        // ???????????????????????? ?????????????????????????????????,???????????????????????????
        boolean login;
        String lang = request.getHeader("lang");
        login = tryLoginTB();

        if(!login){
            log.info("login TB is fail! check the network!");
            return ResponseUtil.unAuth(lang);
        }
        // ?????????????????? ????????????????????????
        String invitationCode =registerReq.getInvitationCode();
        if(StringUtils.isEmpty(invitationCode)){
            // ==??????????????????
            //   ???????????????????????????????????????????????????????????? ?????????mongodb???????????????????????????????????? ?????????????????????
            List<UserAdmin> userAdmins = mongoTemplate.findAll(UserAdmin.class);
            log.info("mongo all users,{}", userAdmins);
            if(userAdmins.size()==0){
                return ResponseUtil.unDefaultUser(lang);
            }
            for (UserAdmin userAdmin:userAdmins){
                if(userAdmin.getRole().equals("default")){
                    //   ????????????????????????????????????????????????????????? ????????????????????????
                    Optional<JsonNode> optional ;
                    try {
                        optional = restClient.getUserToken(UserId.fromString(userAdmin.getUserId()));
                    }catch (Exception e){
                        log.error("tx get userToken err.",e);
                        restClient.logout();
                        return ResponseUtil.unloginByDefaultUser(lang);
                    }
                    if(optional.isPresent()){
                        restClient.setTokenInfo(optional.get());
                        Customer customer;
                        try {
                            customer = restClient.createCustomer(registerReq.getEmail());
                        }catch (Exception e){
                            log.error("tx create customer err.",e);
                            restClient.logout();
                            return ResponseUtil.unCreateCustomer(lang);
                        }
                        User user = new User();
                        user.setEmail(registerReq.getEmail());
                        user.setCustomerId(customer.getId());
                        user.setAuthority(Authority.CUSTOMER_USER);
                        user.setTenantId(customer.getTenantId());
                        try {
                            restClient.saveUser(user,true);
                        }catch (Exception e){
                            log.error("tx create user err.",e);
                            restClient.deleteCustomer(customer.getId());
                            restClient.logout();
                            return ResponseUtil.unCreateUser(lang);
                        }
                    }else {
                        restClient.logout();
                        return ResponseUtil.unloginByDefaultUser(lang);
                    }
                    restClient.logout();
                    return ResponseUtil.ok();
                }
            }
            restClient.logout();
            return ResponseUtil.unDefaultUser(lang);
        }else {
            // ==?????????????????????
            //   ??????????????????????????????mongodb?????????????????????????????????????????????
            List<Tenant> tenants = mongoTemplate.findAll(Tenant.class);
            log.info("mongo all tenants,{}", tenants);
            if(tenants.size()==0){
                return ResponseUtil.unIvitationUser(lang);
            }
            for (Tenant tenant:tenants){
                if(invitationCode.equals(tenant.getInvitationCode())){
                    //   ???????????????????????????????????????????????? ????????????????????????
                    //   ??????????????????????????? ??????????????? ???????????????
                    Optional<JsonNode> optional ;
                    try {
                        optional = restClient.getUserToken(UserId.fromString(tenant.getUserId()));
                    }catch (Exception e){
                        log.error("tx get userToken err.",e);
                        restClient.logout();
                        return ResponseUtil.unloginByDefaultUser(lang);
                    }
                    if(optional.isPresent()){
                        restClient.setTokenInfo(optional.get());
                        Customer customer;
                        try {
                            customer = restClient.createCustomer(registerReq.getEmail());
                        }catch (Exception e){
                            log.error("tx create customer err.",e);
                            restClient.logout();
                            return ResponseUtil.unCreateCustomer(lang);
                        }
                        User user = new User();
                        user.setEmail(registerReq.getEmail());
                        user.setCustomerId(customer.getId());
                        user.setAuthority(Authority.CUSTOMER_USER);
                        user.setTenantId(customer.getTenantId());
                        try {
                            restClient.saveUser(user,true);
                        }catch (Exception e){
                            log.error("tx create user err.",e);
                            restClient.deleteCustomer(customer.getId());
                            restClient.logout();
                            return ResponseUtil.unCreateUser(lang);
                        }
                    }else {
                        restClient.logout();
                        return ResponseUtil.unloginByDefaultUser(lang);
                    }
                    restClient.logout();
                    return ResponseUtil.ok();
                }
            }
            restClient.logout();
            return ResponseUtil.unIvitationUser(lang);
        }
    }


    @RequestMapping("/sendEmail")
    @ResponseBody
    public Object sendEmail(HttpServletRequest request, @RequestBody SendEmailReq sendEmailReq) {
        boolean login;
        String lang = request.getHeader("lang");
        login = tryLoginTB();

        // ?????????????????? ????????????????????????
        String invitationCode = sendEmailReq.getInvitationCode();
        if(StringUtils.isEmpty(invitationCode)){
            // ==??????????????????
            //   ???????????????????????????????????????????????????????????? ?????????mongodb???????????????????????????????????? ?????????????????????
            List<UserAdmin> userAdmins = mongoTemplate.findAll(UserAdmin.class);
            log.info("mongo all users,{}", userAdmins);
            if(userAdmins.size()==0){
                return ResponseUtil.unDefaultUser(lang);
            }
            for (UserAdmin userAdmin:userAdmins){
                if(userAdmin.getRole().equals("default")){
                    //   ????????????????????????????????????????????????????????? ????????????????????????
                    Optional<JsonNode> optional ;
                    try {
                        optional = restClient.getUserToken(UserId.fromString(userAdmin.getUserId()));
                    }catch (Exception e){
                        log.error("tx get userToken err.",e);
                        restClient.logout();
                        return ResponseUtil.unloginByDefaultUser(lang);
                    }
                    if(optional.isPresent()){
                        restClient.setTokenInfo(optional.get());
                        try {
                            restClient.sendActivationEmail(sendEmailReq.getEmail());
                        }catch (Exception e){
                            log.info("send email fail!",e);
                            restClient.logout();
                            return ResponseUtil.unSendEmail(lang);
                        }
                        restClient.logout();
                        return ResponseUtil.ok();
                    }else {
                        restClient.logout();
                        return ResponseUtil.unSendEmail(lang);
                    }
                }
            }
            restClient.logout();
            return ResponseUtil.unSendEmail(lang);
        }else {
            // ==?????????????????????
            //   ??????????????????????????????mongodb?????????????????????????????????????????????
            List<Tenant> tenants = mongoTemplate.findAll(Tenant.class);
            log.info("mongo all tenants,{}", tenants);
            if(tenants.size()==0){
                return ResponseUtil.unIvitationUser(lang);
            }
            for (Tenant tenant:tenants){
                if(invitationCode.equals(tenant.getInvitationCode())){
                    //   ???????????????????????????????????????????????? ????????????????????????
                    //   ??????????????????????????? ??????????????? ???????????????
                    Optional<JsonNode> optional ;
                    try {
                        optional = restClient.getUserToken(UserId.fromString(tenant.getUserId()));
                    }catch (Exception e){
                        log.error("tx get userToken err.",e);
                        restClient.logout();
                        return ResponseUtil.unloginByDefaultUser(lang);
                    }
                    if(optional.isPresent()){
                        restClient.setTokenInfo(optional.get());
                        try {
                            restClient.sendActivationEmail(sendEmailReq.getEmail());
                        }catch (Exception e){
                            log.info("send email fail!",e);
                            restClient.logout();
                            return ResponseUtil.unSendEmail(lang);
                        }
                    }else {
                        restClient.logout();
                        return ResponseUtil.unSendEmail(lang);
                    }
                    restClient.logout();
                    return ResponseUtil.ok();
                }
            }
            restClient.logout();
            return ResponseUtil.unSendEmail(lang);
        }
    }


    @RequestMapping("/tenantAttributes")
    @ResponseBody
    public Object getTenantAttributes(HttpServletRequest request, @RequestBody TenantAttributesReq tenantAttributesReq) {
        boolean login;
        String lang = request.getHeader("lang");
        login = tryLoginTB();

        if(!login){
            log.info("login TB is fail! check the network!");
            return ResponseUtil.unAuth(lang);
        }

        EntityId entityId = new EntityId() {
            @Override
            public UUID getId() {
                return UUID.fromString(tenantAttributesReq.getTenantId());
            }

            @Override
            public EntityType getEntityType() {
                return EntityType.TENANT;
            }
        };

        List<AttributeKvEntry> attributeKvEntries = null;
        try {
            attributeKvEntries = restClient.getAttributeKvEntries(entityId, tenantAttributesReq.getKeys());
        } catch (Exception e) {
            log.info("getTenantAttributes err,{}", e);
            restClient.logout();
            return ResponseUtil.fail(401, e.getMessage());
        }
        restClient.logout();
        return ResponseUtil.ok(attributeKvEntries);
    }

    private boolean tryLoginTB(){
        boolean result = false;
        try {
            restClient.getRestTemplate().getInterceptors().remove(restClient);
            List<UserAdmin> userAdmins = mongoTemplate.findAll(UserAdmin.class);
            log.info("mongo all users,{}", userAdmins);
            if (userAdmins.size() == 0) {
                restClient.login(thingsBoardRestClientConfig.userName, thingsBoardRestClientConfig.passWord);
                result = true;
            } else {
                for(UserAdmin userAdmin : userAdmins){
                    if(userAdmin.getRole().equals("admin")){
                        restClient.login(userAdmin.getName(), userAdmin.getPassWord());
                        return true;
                    }
                }
                log.info("mongo can not find admin");
                return false;
            }
        } catch (Exception e) {
            log.info("tb login err", e);
        }
        return result;
    }

}
