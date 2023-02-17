package com.tahu.thingsx.txserver.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.support.HttpRequestWrapper;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.thingsboard.rest.client.utils.RestJsonConverter;
import org.thingsboard.server.common.data.*;
import org.thingsboard.server.common.data.alarm.*;
import org.thingsboard.server.common.data.asset.Asset;
import org.thingsboard.server.common.data.asset.AssetSearchQuery;
import org.thingsboard.server.common.data.audit.ActionType;
import org.thingsboard.server.common.data.audit.AuditLog;
import org.thingsboard.server.common.data.device.DeviceSearchQuery;
import org.thingsboard.server.common.data.entityview.EntityViewSearchQuery;
import org.thingsboard.server.common.data.id.*;
import org.thingsboard.server.common.data.kv.Aggregation;
import org.thingsboard.server.common.data.kv.AttributeKvEntry;
import org.thingsboard.server.common.data.kv.TsKvEntry;
import org.thingsboard.server.common.data.page.PageData;
import org.thingsboard.server.common.data.page.PageLink;
import org.thingsboard.server.common.data.page.TimePageLink;
import org.thingsboard.server.common.data.plugin.ComponentDescriptor;
import org.thingsboard.server.common.data.plugin.ComponentType;
import org.thingsboard.server.common.data.relation.EntityRelation;
import org.thingsboard.server.common.data.relation.EntityRelationInfo;
import org.thingsboard.server.common.data.relation.EntityRelationsQuery;
import org.thingsboard.server.common.data.relation.RelationTypeGroup;
import org.thingsboard.server.common.data.rule.RuleChain;
import org.thingsboard.server.common.data.rule.RuleChainMetaData;
import org.thingsboard.server.common.data.security.DeviceCredentials;
import org.thingsboard.server.common.data.security.DeviceCredentialsType;
import org.thingsboard.server.common.data.security.model.SecuritySettings;
import org.thingsboard.server.common.data.security.model.UserPasswordPolicy;
import org.thingsboard.server.common.data.widget.WidgetType;
import org.thingsboard.server.common.data.widget.WidgetsBundle;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

public class TXRestClient implements ClientHttpRequestInterceptor, Closeable {
    private static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
    protected final RestTemplate restTemplate;
    protected final String baseURL;
    private String token;
    private String refreshToken;
    private final ObjectMapper objectMapper;
    private ExecutorService service;
    protected static final String ACTIVATE_TOKEN_REGEX = "/api/noauth/activate?activateToken=";

    public TXRestClient(String baseURL) {
        this(new RestTemplate(), baseURL);
    }

    public TXRestClient(RestTemplate restTemplate, String baseURL) {
        this.objectMapper = new ObjectMapper();
        this.service = Executors.newWorkStealingPool(10);
        this.restTemplate = restTemplate;
        this.baseURL = baseURL;
    }

    public ClientHttpResponse intercept(HttpRequest request, byte[] bytes, ClientHttpRequestExecution execution) throws IOException {
        HttpRequest wrapper = new HttpRequestWrapper(request);
        wrapper.getHeaders().set("X-Authorization", "Bearer " + this.token);
        ClientHttpResponse response = execution.execute(wrapper, bytes);
        if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            synchronized(this) {
                this.restTemplate.getInterceptors().remove(this);
                this.refreshToken();
                wrapper.getHeaders().set("X-Authorization", "Bearer " + this.token);
                return execution.execute(wrapper, bytes);
            }
        } else {
            return response;
        }
    }

    public RestTemplate getRestTemplate() {
        return this.restTemplate;
    }

    public String getToken() {
        return this.token;
    }

    public String getRefreshToken() {
        return this.refreshToken;
    }

    public void refreshToken() {
        Map<String, String> refreshTokenRequest = new HashMap();
        refreshTokenRequest.put("refreshToken", this.refreshToken);
        ResponseEntity<JsonNode> tokenInfo = this.restTemplate.postForEntity(this.baseURL + "/api/auth/token", refreshTokenRequest, JsonNode.class, new Object[0]);
        this.setTokenInfo((JsonNode)tokenInfo.getBody());
    }

    public void login(String username, String password) {
        Map<String, String> loginRequest = new HashMap();
        loginRequest.put("username", username);
        loginRequest.put("password", password);
        ResponseEntity<JsonNode> tokenInfo = this.restTemplate.postForEntity(this.baseURL + "/api/auth/login", loginRequest, JsonNode.class, new Object[0]);
        this.setTokenInfo((JsonNode)tokenInfo.getBody());
    }

    public void setTokenInfo(JsonNode tokenInfo) {
        this.token = tokenInfo.get("token").asText();
        this.refreshToken = tokenInfo.get("refreshToken").asText();
        this.restTemplate.getInterceptors().add(this);
    }

    public Optional<AdminSettings> getAdminSettings(String key) {
        try {
            ResponseEntity<AdminSettings> adminSettings = this.restTemplate.getForEntity(this.baseURL + "/api/admin/settings/{key}", AdminSettings.class, new Object[]{key});
            return Optional.ofNullable(adminSettings.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public AdminSettings saveAdminSettings(AdminSettings adminSettings) {
        return (AdminSettings)this.restTemplate.postForEntity(this.baseURL + "/api/admin/settings", adminSettings, AdminSettings.class, new Object[0]).getBody();
    }

    public void sendTestMail(AdminSettings adminSettings) {
        this.restTemplate.postForEntity(this.baseURL + "/api/admin/settings/testMail", adminSettings, AdminSettings.class, new Object[0]);
    }

    public Optional<SecuritySettings> getSecuritySettings() {
        try {
            ResponseEntity<SecuritySettings> securitySettings = this.restTemplate.getForEntity(this.baseURL + "/api/admin/securitySettings", SecuritySettings.class, new Object[0]);
            return Optional.ofNullable(securitySettings.getBody());
        } catch (HttpClientErrorException var2) {
            if (var2.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var2;
            }
        }
    }

    public SecuritySettings saveSecuritySettings(SecuritySettings securitySettings) {
        return (SecuritySettings)this.restTemplate.postForEntity(this.baseURL + "/api/admin/securitySettings", securitySettings, SecuritySettings.class, new Object[0]).getBody();
    }

    public Optional<UpdateMessage> checkUpdates() {
        try {
            ResponseEntity<UpdateMessage> updateMsg = this.restTemplate.getForEntity(this.baseURL + "/api/admin/updates", UpdateMessage.class, new Object[0]);
            return Optional.ofNullable(updateMsg.getBody());
        } catch (HttpClientErrorException var2) {
            if (var2.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var2;
            }
        }
    }

    public Optional<Alarm> getAlarmById(AlarmId alarmId) {
        try {
            ResponseEntity<Alarm> alarm = this.restTemplate.getForEntity(this.baseURL + "/api/alarm/{alarmId}", Alarm.class, new Object[]{alarmId.getId()});
            return Optional.ofNullable(alarm.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<AlarmInfo> getAlarmInfoById(AlarmId alarmId) {
        try {
            ResponseEntity<AlarmInfo> alarmInfo = this.restTemplate.getForEntity(this.baseURL + "/api/alarm/info/{alarmId}", AlarmInfo.class, new Object[]{alarmId.getId()});
            return Optional.ofNullable(alarmInfo.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Alarm saveAlarm(Alarm alarm) {
        return (Alarm)this.restTemplate.postForEntity(this.baseURL + "/api/alarm", alarm, Alarm.class, new Object[0]).getBody();
    }

    public void deleteAlarm(AlarmId alarmId) {
        this.restTemplate.delete(this.baseURL + "/api/alarm/{alarmId}", new Object[]{alarmId.getId()});
    }

    public void ackAlarm(AlarmId alarmId) {
        this.restTemplate.postForLocation(this.baseURL + "/api/alarm/{alarmId}/ack", (Object)null, new Object[]{alarmId.getId()});
    }

    public void clearAlarm(AlarmId alarmId) {
        this.restTemplate.postForLocation(this.baseURL + "/api/alarm/{alarmId}/clear", (Object)null, new Object[]{alarmId.getId()});
    }

    public PageData<AlarmInfo> getAlarms(EntityId entityId, AlarmSearchStatus searchStatus, AlarmStatus status, TimePageLink pageLink, Boolean fetchOriginator) {
        Map<String, String> params = new HashMap();
        params.put("entityType", entityId.getEntityType().name());
        params.put("entityId", entityId.getId().toString());
        params.put("searchStatus", searchStatus.name());
        params.put("status", status.name());
        params.put("fetchOriginator", String.valueOf(fetchOriginator));
        this.addTimePageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/alarm/{entityType}/{entityId}?searchStatus={searchStatus}&status={status}&fetchOriginator={fetchOriginator}&" + this.getTimeUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<AlarmInfo>>() {
        }, params).getBody();
    }

    public Optional<AlarmSeverity> getHighestAlarmSeverity(EntityId entityId, AlarmSearchStatus searchStatus, AlarmStatus status) {
        Map<String, String> params = new HashMap();
        params.put("entityType", entityId.getEntityType().name());
        params.put("entityId", entityId.getId().toString());
        params.put("searchStatus", searchStatus.name());
        params.put("status", status.name());

        try {
            ResponseEntity<AlarmSeverity> alarmSeverity = this.restTemplate.getForEntity(this.baseURL + "/api/alarm/highestSeverity/{entityType}/{entityId}?searchStatus={searchStatus}&status={status}", AlarmSeverity.class, params);
            return Optional.ofNullable(alarmSeverity.getBody());
        } catch (HttpClientErrorException var6) {
            if (var6.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var6;
            }
        }
    }

    /** @deprecated */
    @Deprecated
    public Alarm createAlarm(Alarm alarm) {
        return (Alarm)this.restTemplate.postForEntity(this.baseURL + "/api/alarm", alarm, Alarm.class, new Object[0]).getBody();
    }

    public Optional<Asset> getAssetById(AssetId assetId) {
        try {
            ResponseEntity<Asset> asset = this.restTemplate.getForEntity(this.baseURL + "/api/asset/{assetId}", Asset.class, new Object[]{assetId.getId()});
            return Optional.ofNullable(asset.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Asset saveAsset(Asset asset) {
        return (Asset)this.restTemplate.postForEntity(this.baseURL + "/api/asset", asset, Asset.class, new Object[0]).getBody();
    }

    public void deleteAsset(AssetId assetId) {
        this.restTemplate.delete(this.baseURL + "/api/asset/{assetId}", new Object[]{assetId.getId()});
    }

    public Optional<Asset> assignAssetToCustomer(CustomerId customerId, AssetId assetId) {
        Map<String, String> params = new HashMap();
        params.put("customerId", customerId.getId().toString());
        params.put("assetId", assetId.getId().toString());

        try {
            ResponseEntity<Asset> asset = this.restTemplate.postForEntity(this.baseURL + "/api/customer/{customerId}/asset/{assetId}", (Object)null, Asset.class, params);
            return Optional.ofNullable(asset.getBody());
        } catch (HttpClientErrorException var5) {
            if (var5.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var5;
            }
        }
    }

    public Optional<Asset> unassignAssetFromCustomer(AssetId assetId) {
        try {
            ResponseEntity<Asset> asset = this.restTemplate.exchange(this.baseURL + "/api/customer/asset/{assetId}", HttpMethod.DELETE, HttpEntity.EMPTY, Asset.class, new Object[]{assetId.getId()});
            return Optional.ofNullable(asset.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<Asset> assignAssetToPublicCustomer(AssetId assetId) {
        try {
            ResponseEntity<Asset> asset = this.restTemplate.postForEntity(this.baseURL + "/api/customer/public/asset/{assetId}", (Object)null, Asset.class, new Object[]{assetId.getId()});
            return Optional.ofNullable(asset.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public PageData<Asset> getTenantAssets(PageLink pageLink, String assetType) {
        Map<String, String> params = new HashMap();
        params.put("type", assetType);
        this.addPageLinkToParam(params, pageLink);
        ResponseEntity<PageData<Asset>> assets = this.restTemplate.exchange(this.baseURL + "/api/tenant/assets?type={type}&" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<Asset>>() {
        }, params);
        return (PageData)assets.getBody();
    }

    public Optional<Asset> getTenantAsset(String assetName) {
        try {
            ResponseEntity<Asset> asset = this.restTemplate.getForEntity(this.baseURL + "/api/tenant/assets?assetName={assetName}", Asset.class, new Object[]{assetName});
            return Optional.ofNullable(asset.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public PageData<Asset> getCustomerAssets(CustomerId customerId, PageLink pageLink, String assetType) {
        Map<String, String> params = new HashMap();
        params.put("customerId", customerId.getId().toString());
        params.put("type", assetType);
        this.addPageLinkToParam(params, pageLink);
        ResponseEntity<PageData<Asset>> assets = this.restTemplate.exchange(this.baseURL + "/api/customer/{customerId}/assets?type={type}&" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<Asset>>() {
        }, params);
        return (PageData)assets.getBody();
    }

    public List<Asset> getAssetsByIds(List<AssetId> assetIds) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/assets?assetIds={assetIds}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<Asset>>() {
        }, new Object[]{this.listIdsToString(assetIds)}).getBody();
    }

    public List<Asset> findByQuery(AssetSearchQuery query) {
        return (List)this.restTemplate.exchange(URI.create(this.baseURL + "/api/assets"), HttpMethod.POST, new HttpEntity(query), new ParameterizedTypeReference<List<Asset>>() {
        }).getBody();
    }

    public List<EntitySubtype> getAssetTypes() {
        return (List)this.restTemplate.exchange(URI.create(this.baseURL + "/api/asset/types"), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntitySubtype>>() {
        }).getBody();
    }

    /** @deprecated */
    @Deprecated
    public Optional<Asset> findAsset(String name) {
        Map<String, String> params = new HashMap();
        params.put("assetName", name);

        try {
            ResponseEntity<Asset> assetEntity = this.restTemplate.getForEntity(this.baseURL + "/api/tenant/assets?assetName={assetName}", Asset.class, params);
            return Optional.of(assetEntity.getBody());
        } catch (HttpClientErrorException var4) {
            if (var4.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var4;
            }
        }
    }

    /** @deprecated */
    @Deprecated
    public Asset createAsset(Asset asset) {
        return (Asset)this.restTemplate.postForEntity(this.baseURL + "/api/asset", asset, Asset.class, new Object[0]).getBody();
    }

    /** @deprecated */
    @Deprecated
    public Asset createAsset(String name, String type) {
        Asset asset = new Asset();
        asset.setName(name);
        asset.setType(type);
        return (Asset)this.restTemplate.postForEntity(this.baseURL + "/api/asset", asset, Asset.class, new Object[0]).getBody();
    }

    /** @deprecated */
    @Deprecated
    public Asset assignAsset(CustomerId customerId, AssetId assetId) {
        return (Asset)this.restTemplate.postForEntity(this.baseURL + "/api/customer/{customerId}/asset/{assetId}", HttpEntity.EMPTY, Asset.class, new Object[]{customerId.toString(), assetId.toString()}).getBody();
    }

    public PageData<AuditLog> getAuditLogsByCustomerId(CustomerId customerId, TimePageLink pageLink, List<ActionType> actionTypes) {
        Map<String, String> params = new HashMap();
        params.put("customerId", customerId.getId().toString());
        params.put("actionTypes", this.listEnumToString(actionTypes));
        this.addTimePageLinkToParam(params, pageLink);
        ResponseEntity<PageData<AuditLog>> auditLog = this.restTemplate.exchange(this.baseURL + "/api/audit/logs/customer/{customerId}?actionTypes={actionTypes}&" + this.getTimeUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<AuditLog>>() {
        }, params);
        return (PageData)auditLog.getBody();
    }

    public PageData<AuditLog> getAuditLogsByUserId(UserId userId, TimePageLink pageLink, List<ActionType> actionTypes) {
        Map<String, String> params = new HashMap();
        params.put("userId", userId.getId().toString());
        params.put("actionTypes", this.listEnumToString(actionTypes));
        this.addTimePageLinkToParam(params, pageLink);
        ResponseEntity<PageData<AuditLog>> auditLog = this.restTemplate.exchange(this.baseURL + "/api/audit/logs/user/{userId}?actionTypes={actionTypes}&" + this.getTimeUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<AuditLog>>() {
        }, params);
        return (PageData)auditLog.getBody();
    }

    public PageData<AuditLog> getAuditLogsByEntityId(EntityId entityId, List<ActionType> actionTypes, TimePageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("entityType", entityId.getEntityType().name());
        params.put("entityId", entityId.getId().toString());
        params.put("actionTypes", this.listEnumToString(actionTypes));
        this.addTimePageLinkToParam(params, pageLink);
        ResponseEntity<PageData<AuditLog>> auditLog = this.restTemplate.exchange(this.baseURL + "/api/audit/logs/entity/{entityType}/{entityId}?actionTypes={actionTypes}&" + this.getTimeUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<AuditLog>>() {
        }, params);
        return (PageData)auditLog.getBody();
    }

    public PageData<AuditLog> getAuditLogs(TimePageLink pageLink, List<ActionType> actionTypes) {
        Map<String, String> params = new HashMap();
        params.put("actionTypes", this.listEnumToString(actionTypes));
        this.addTimePageLinkToParam(params, pageLink);
        ResponseEntity<PageData<AuditLog>> auditLog = this.restTemplate.exchange(this.baseURL + "/api/audit/logs?actionTypes={actionTypes}&" + this.getTimeUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<AuditLog>>() {
        }, params);
        return (PageData)auditLog.getBody();
    }

    public String getActivateToken(UserId userId) {
        String activationLink = this.getActivationLink(userId);
        return activationLink.substring(activationLink.lastIndexOf("/api/noauth/activate?activateToken=") + "/api/noauth/activate?activateToken=".length());
    }

    public Optional<User> getUser() {
        ResponseEntity<User> user = this.restTemplate.getForEntity(this.baseURL + "/api/auth/user", User.class, new Object[0]);
        return Optional.ofNullable(user.getBody());
    }

    public void logout() {
        this.restTemplate.postForLocation(this.baseURL + "/api/auth/logout", (Object)null, new Object[0]);
    }

    public void changePassword(String currentPassword, String newPassword) {
        ObjectNode changePasswordRequest = this.objectMapper.createObjectNode();
        changePasswordRequest.put("currentPassword", currentPassword);
        changePasswordRequest.put("newPassword", newPassword);
        this.restTemplate.postForLocation(this.baseURL + "/api/auth/changePassword", changePasswordRequest, new Object[0]);
    }

    public Optional<UserPasswordPolicy> getUserPasswordPolicy() {
        try {
            ResponseEntity<UserPasswordPolicy> userPasswordPolicy = this.restTemplate.getForEntity(this.baseURL + "/api/noauth/userPasswordPolicy", UserPasswordPolicy.class, new Object[0]);
            return Optional.ofNullable(userPasswordPolicy.getBody());
        } catch (HttpClientErrorException var2) {
            if (var2.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var2;
            }
        }
    }

    public ResponseEntity<String> checkActivateToken(UserId userId) {
        String activateToken = this.getActivateToken(userId);
        return this.restTemplate.getForEntity(this.baseURL + "/api/noauth/activate?activateToken={activateToken}", String.class, new Object[]{activateToken});
    }

    public void requestResetPasswordByEmail(String email) {
        ObjectNode resetPasswordByEmailRequest = this.objectMapper.createObjectNode();
        resetPasswordByEmailRequest.put("email", email);
        this.restTemplate.postForLocation(this.baseURL + "/api/noauth/resetPasswordByEmail", resetPasswordByEmailRequest, new Object[0]);
    }

    public Optional<JsonNode> activateUser(UserId userId, String password) {
        ObjectNode activateRequest = this.objectMapper.createObjectNode();
        activateRequest.put("activateToken", this.getActivateToken(userId));
        activateRequest.put("password", password);

        try {
            ResponseEntity<JsonNode> jsonNode = this.restTemplate.postForEntity(this.baseURL + "/api/noauth/activate", activateRequest, JsonNode.class, new Object[0]);
            return Optional.ofNullable(jsonNode.getBody());
        } catch (HttpClientErrorException var5) {
            if (var5.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var5;
            }
        }
    }

    public Optional<ComponentDescriptor> getComponentDescriptorByClazz(String componentDescriptorClazz) {
        try {
            ResponseEntity<ComponentDescriptor> componentDescriptor = this.restTemplate.getForEntity(this.baseURL + "/api/component/{componentDescriptorClazz}", ComponentDescriptor.class, new Object[]{componentDescriptorClazz});
            return Optional.ofNullable(componentDescriptor.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public List<ComponentDescriptor> getComponentDescriptorsByType(ComponentType componentType) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/components?componentType={componentType}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<ComponentDescriptor>>() {
        }, new Object[]{componentType}).getBody();
    }

    public List<ComponentDescriptor> getComponentDescriptorsByTypes(List<ComponentType> componentTypes) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/components?componentTypes={componentTypes}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<ComponentDescriptor>>() {
        }, new Object[]{this.listEnumToString(componentTypes)}).getBody();
    }

    public Optional<Customer> getCustomerById(CustomerId customerId) {
        try {
            ResponseEntity<Customer> customer = this.restTemplate.getForEntity(this.baseURL + "/api/customer/{customerId}", Customer.class, new Object[]{customerId.getId()});
            return Optional.ofNullable(customer.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<JsonNode> getShortCustomerInfoById(CustomerId customerId) {
        try {
            ResponseEntity<JsonNode> customerInfo = this.restTemplate.getForEntity(this.baseURL + "/api/customer/{customerId}/shortInfo", JsonNode.class, new Object[]{customerId.getId()});
            return Optional.ofNullable(customerInfo.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public String getCustomerTitleById(CustomerId customerId) {
        return (String)this.restTemplate.getForObject(this.baseURL + "/api/customer/{customerId}/title", String.class, new Object[]{customerId.getId()});
    }

    public Customer saveCustomer(Customer customer) {
        return (Customer)this.restTemplate.postForEntity(this.baseURL + "/api/customer", customer, Customer.class, new Object[0]).getBody();
    }

    public void deleteCustomer(CustomerId customerId) {
        this.restTemplate.delete(this.baseURL + "/api/customer/{customerId}", new Object[]{customerId.getId()});
    }

    public PageData<Customer> getCustomers(PageLink pageLink) {
        Map<String, String> params = new HashMap();
        this.addPageLinkToParam(params, pageLink);
        ResponseEntity<PageData<Customer>> customer = this.restTemplate.exchange(this.baseURL + "/api/customers?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<Customer>>() {
        }, params);
        return (PageData)customer.getBody();
    }

    public Optional<Customer> getTenantCustomer(String customerTitle) {
        try {
            ResponseEntity<Customer> customer = this.restTemplate.getForEntity(this.baseURL + "/api/tenant/customers?customerTitle={customerTitle}", Customer.class, new Object[]{customerTitle});
            return Optional.ofNullable(customer.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    /** @deprecated */
    @Deprecated
    public Optional<Customer> findCustomer(String title) {
        Map<String, String> params = new HashMap();
        params.put("customerTitle", title);

        try {
            ResponseEntity<Customer> customerEntity = this.restTemplate.getForEntity(this.baseURL + "/api/tenant/customers?customerTitle={customerTitle}", Customer.class, params);
            return Optional.of(customerEntity.getBody());
        } catch (HttpClientErrorException var4) {
            if (var4.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var4;
            }
        }
    }

    /** @deprecated */
    @Deprecated
    public Customer createCustomer(Customer customer) {
        return (Customer)this.restTemplate.postForEntity(this.baseURL + "/api/customer", customer, Customer.class, new Object[0]).getBody();
    }

    /** @deprecated */
    @Deprecated
    public Customer createCustomer(String title) {
        Customer customer = new Customer();
        customer.setTitle(title);
        return (Customer)this.restTemplate.postForEntity(this.baseURL + "/api/customer", customer, Customer.class, new Object[0]).getBody();
    }

    public Long getServerTime() {
        return (Long)this.restTemplate.getForObject(this.baseURL + "/api/dashboard/serverTime", Long.class, new Object[0]);
    }

    public Long getMaxDatapointsLimit() {
        return (Long)this.restTemplate.getForObject(this.baseURL + "/api/dashboard/maxDatapointsLimit", Long.class, new Object[0]);
    }

    public Optional<DashboardInfo> getDashboardInfoById(DashboardId dashboardId) {
        try {
            ResponseEntity<DashboardInfo> dashboardInfo = this.restTemplate.getForEntity(this.baseURL + "/api/dashboard/info/{dashboardId}", DashboardInfo.class, new Object[]{dashboardId.getId()});
            return Optional.ofNullable(dashboardInfo.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<Dashboard> getDashboardById(DashboardId dashboardId) {
        try {
            ResponseEntity<Dashboard> dashboard = this.restTemplate.getForEntity(this.baseURL + "/api/dashboard/{dashboardId}", Dashboard.class, new Object[]{dashboardId.getId()});
            return Optional.ofNullable(dashboard.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Dashboard saveDashboard(Dashboard dashboard) {
        return (Dashboard)this.restTemplate.postForEntity(this.baseURL + "/api/dashboard", dashboard, Dashboard.class, new Object[0]).getBody();
    }

    public void deleteDashboard(DashboardId dashboardId) {
        this.restTemplate.delete(this.baseURL + "/api/dashboard/{dashboardId}", new Object[]{dashboardId.getId()});
    }

    public Optional<Dashboard> assignDashboardToCustomer(CustomerId customerId, DashboardId dashboardId) {
        try {
            ResponseEntity<Dashboard> dashboard = this.restTemplate.postForEntity(this.baseURL + "/api/customer/{customerId}/dashboard/{dashboardId}", (Object)null, Dashboard.class, new Object[]{customerId.getId(), dashboardId.getId()});
            return Optional.ofNullable(dashboard.getBody());
        } catch (HttpClientErrorException var4) {
            if (var4.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var4;
            }
        }
    }

    public Optional<Dashboard> unassignDashboardFromCustomer(CustomerId customerId, DashboardId dashboardId) {
        try {
            ResponseEntity<Dashboard> dashboard = this.restTemplate.exchange(this.baseURL + "/api/customer/{customerId}/dashboard/{dashboardId}", HttpMethod.DELETE, HttpEntity.EMPTY, Dashboard.class, new Object[]{customerId.getId(), dashboardId.getId()});
            return Optional.ofNullable(dashboard.getBody());
        } catch (HttpClientErrorException var4) {
            if (var4.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var4;
            }
        }
    }

    public Optional<Dashboard> updateDashboardCustomers(DashboardId dashboardId, List<CustomerId> customerIds) {
        Object[] customerIdArray = customerIds.stream().map((customerId) -> {
            return customerId.getId().toString();
        }).toArray();

        try {
            ResponseEntity<Dashboard> dashboard = this.restTemplate.postForEntity(this.baseURL + "/api/dashboard/{dashboardId}/customers", customerIdArray, Dashboard.class, new Object[]{dashboardId.getId()});
            return Optional.ofNullable(dashboard.getBody());
        } catch (HttpClientErrorException var5) {
            if (var5.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var5;
            }
        }
    }

    public Optional<Dashboard> addDashboardCustomers(DashboardId dashboardId, List<CustomerId> customerIds) {
        Object[] customerIdArray = customerIds.stream().map((customerId) -> {
            return customerId.getId().toString();
        }).toArray();

        try {
            ResponseEntity<Dashboard> dashboard = this.restTemplate.postForEntity(this.baseURL + "/api/dashboard/{dashboardId}/customers/add", customerIdArray, Dashboard.class, new Object[]{dashboardId.getId()});
            return Optional.ofNullable(dashboard.getBody());
        } catch (HttpClientErrorException var5) {
            if (var5.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var5;
            }
        }
    }

    public Optional<Dashboard> removeDashboardCustomers(DashboardId dashboardId, List<CustomerId> customerIds) {
        Object[] customerIdArray = customerIds.stream().map((customerId) -> {
            return customerId.getId().toString();
        }).toArray();

        try {
            ResponseEntity<Dashboard> dashboard = this.restTemplate.postForEntity(this.baseURL + "/api/dashboard/{dashboardId}/customers/remove", customerIdArray, Dashboard.class, new Object[]{dashboardId.getId()});
            return Optional.ofNullable(dashboard.getBody());
        } catch (HttpClientErrorException var5) {
            if (var5.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var5;
            }
        }
    }

    public Optional<Dashboard> assignDashboardToPublicCustomer(DashboardId dashboardId) {
        try {
            ResponseEntity<Dashboard> dashboard = this.restTemplate.postForEntity(this.baseURL + "/api/customer/public/dashboard/{dashboardId}", (Object)null, Dashboard.class, new Object[]{dashboardId.getId()});
            return Optional.ofNullable(dashboard.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<Dashboard> unassignDashboardFromPublicCustomer(DashboardId dashboardId) {
        try {
            ResponseEntity<Dashboard> dashboard = this.restTemplate.exchange(this.baseURL + "/api/customer/public/dashboard/{dashboardId}", HttpMethod.DELETE, HttpEntity.EMPTY, Dashboard.class, new Object[]{dashboardId.getId()});
            return Optional.ofNullable(dashboard.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public PageData<DashboardInfo> getTenantDashboards(TenantId tenantId, PageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("tenantId", tenantId.getId().toString());
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/tenant/{tenantId}/dashboards?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<DashboardInfo>>() {
        }, params).getBody();
    }

    public PageData<DashboardInfo> getTenantDashboards(PageLink pageLink) {
        Map<String, String> params = new HashMap();
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/tenant/dashboards?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<DashboardInfo>>() {
        }, params).getBody();
    }

    public PageData<DashboardInfo> getCustomerDashboards(CustomerId customerId, TimePageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("customerId", customerId.getId().toString());
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/customer/{customerId}/dashboards?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<DashboardInfo>>() {
        }, params).getBody();
    }

    /** @deprecated */
    @Deprecated
    public Dashboard createDashboard(Dashboard dashboard) {
        return (Dashboard)this.restTemplate.postForEntity(this.baseURL + "/api/dashboard", dashboard, Dashboard.class, new Object[0]).getBody();
    }

    /** @deprecated */
    @Deprecated
    public List<DashboardInfo> findTenantDashboards() {
        try {
            ResponseEntity<PageData<DashboardInfo>> dashboards = this.restTemplate.exchange(this.baseURL + "/api/tenant/dashboards?pageSize=100000", HttpMethod.GET, (HttpEntity)null, new ParameterizedTypeReference<PageData<DashboardInfo>>() {
            }, new Object[0]);
            return ((PageData)dashboards.getBody()).getData();
        } catch (HttpClientErrorException var2) {
            if (var2.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Collections.emptyList();
            } else {
                throw var2;
            }
        }
    }

    public Optional<Device> getDeviceById(DeviceId deviceId) {
        try {
            ResponseEntity<Device> device = this.restTemplate.getForEntity(this.baseURL + "/api/device/{deviceId}", Device.class, new Object[]{deviceId.getId()});
            return Optional.ofNullable(device.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Device saveDevice(Device device) {
        return (Device)this.restTemplate.postForEntity(this.baseURL + "/api/device", device, Device.class, new Object[0]).getBody();
    }

    public void deleteDevice(DeviceId deviceId) {
        this.restTemplate.delete(this.baseURL + "/api/device/{deviceId}", new Object[]{deviceId.getId()});
    }

    public Optional<Device> assignDeviceToCustomer(CustomerId customerId, DeviceId deviceId) {
        try {
            ResponseEntity<Device> device = this.restTemplate.postForEntity(this.baseURL + "/api/customer/{customerId}/device/{deviceId}", (Object)null, Device.class, new Object[]{customerId.getId(), deviceId.getId()});
            return Optional.ofNullable(device.getBody());
        } catch (HttpClientErrorException var4) {
            if (var4.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var4;
            }
        }
    }

    public Optional<Device> unassignDeviceFromCustomer(DeviceId deviceId) {
        try {
            ResponseEntity<Device> device = this.restTemplate.exchange(this.baseURL + "/api/customer/device/{deviceId}", HttpMethod.DELETE, HttpEntity.EMPTY, Device.class, new Object[]{deviceId.getId()});
            return Optional.ofNullable(device.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<Device> assignDeviceToPublicCustomer(DeviceId deviceId) {
        try {
            ResponseEntity<Device> device = this.restTemplate.postForEntity(this.baseURL + "/api/customer/public/device/{deviceId}", (Object)null, Device.class, new Object[]{deviceId.getId()});
            return Optional.ofNullable(device.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<DeviceCredentials> getDeviceCredentialsByDeviceId(DeviceId deviceId) {
        try {
            ResponseEntity<DeviceCredentials> deviceCredentials = this.restTemplate.getForEntity(this.baseURL + "/api/device/{deviceId}/credentials", DeviceCredentials.class, new Object[]{deviceId.getId()});
            return Optional.ofNullable(deviceCredentials.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public DeviceCredentials saveDeviceCredentials(DeviceCredentials deviceCredentials) {
        return (DeviceCredentials)this.restTemplate.postForEntity(this.baseURL + "/api/device/credentials", deviceCredentials, DeviceCredentials.class, new Object[0]).getBody();
    }

    public PageData<Device> getTenantDevices(String type, PageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("type", type);
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/tenant/devices?type={type}&" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<Device>>() {
        }, params).getBody();
    }

    public Optional<Device> getTenantDevice(String deviceName) {
        try {
            ResponseEntity<Device> device = this.restTemplate.getForEntity(this.baseURL + "/api/tenant/devices?deviceName={deviceName}", Device.class, new Object[]{deviceName});
            return Optional.ofNullable(device.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public PageData<Device> getCustomerDevices(CustomerId customerId, String deviceType, PageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("customerId", customerId.getId().toString());
        params.put("type", deviceType);
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/customer/{customerId}/devices?type={type}&" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<Device>>() {
        }, params).getBody();
    }

    public List<Device> getDevicesByIds(List<DeviceId> deviceIds) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/devices?deviceIds={deviceIds}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<Device>>() {
        }, new Object[]{this.listIdsToString(deviceIds)}).getBody();
    }

    public List<Device> findByQuery(DeviceSearchQuery query) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/devices", HttpMethod.POST, new HttpEntity(query), new ParameterizedTypeReference<List<Device>>() {
        }, new Object[0]).getBody();
    }

    public List<EntitySubtype> getDeviceTypes() {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/devices", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntitySubtype>>() {
        }, new Object[0]).getBody();
    }

    public JsonNode claimDevice(String deviceName, ClaimRequest claimRequest) {
        return (JsonNode)this.restTemplate.exchange(this.baseURL + "/api/customer/device/{deviceName}/claim", HttpMethod.POST, new HttpEntity(claimRequest), new ParameterizedTypeReference<JsonNode>() {
        }, new Object[]{deviceName}).getBody();
    }

    public void reClaimDevice(String deviceName) {
        this.restTemplate.delete(this.baseURL + "/api/customer/device/{deviceName}/claim", new Object[]{deviceName});
    }

    /** @deprecated */
    @Deprecated
    public Device createDevice(String name, String type) {
        Device device = new Device();
        device.setName(name);
        device.setType(type);
        return this.doCreateDevice(device, (String)null);
    }

    /** @deprecated */
    @Deprecated
    public Device createDevice(Device device) {
        return this.doCreateDevice(device, (String)null);
    }

    /** @deprecated */
    @Deprecated
    public Device createDevice(Device device, String accessToken) {
        return this.doCreateDevice(device, accessToken);
    }

    /** @deprecated */
    @Deprecated
    private Device doCreateDevice(Device device, String accessToken) {
        Map<String, String> params = new HashMap();
        String deviceCreationUrl = "/api/device";
        if (!StringUtils.isEmpty(accessToken)) {
            deviceCreationUrl = deviceCreationUrl + "?accessToken={accessToken}";
            params.put("accessToken", accessToken);
        }

        return (Device)this.restTemplate.postForEntity(this.baseURL + deviceCreationUrl, device, Device.class, params).getBody();
    }

    /** @deprecated */
    @Deprecated
    public DeviceCredentials getCredentials(DeviceId id) {
        return (DeviceCredentials)this.restTemplate.getForEntity(this.baseURL + "/api/device/" + id.getId().toString() + "/credentials", DeviceCredentials.class, new Object[0]).getBody();
    }

    /** @deprecated */
    @Deprecated
    public Optional<Device> findDevice(String name) {
        Map<String, String> params = new HashMap();
        params.put("deviceName", name);

        try {
            ResponseEntity<Device> deviceEntity = this.restTemplate.getForEntity(this.baseURL + "/api/tenant/devices?deviceName={deviceName}", Device.class, params);
            return Optional.of(deviceEntity.getBody());
        } catch (HttpClientErrorException var4) {
            if (var4.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var4;
            }
        }
    }

    /** @deprecated */
    @Deprecated
    public DeviceCredentials updateDeviceCredentials(DeviceId deviceId, String token) {
        DeviceCredentials deviceCredentials = this.getCredentials(deviceId);
        deviceCredentials.setCredentialsType(DeviceCredentialsType.ACCESS_TOKEN);
        deviceCredentials.setCredentialsId(token);
        return this.saveDeviceCredentials(deviceCredentials);
    }

    /** @deprecated */
    @Deprecated
    public Device assignDevice(CustomerId customerId, DeviceId deviceId) {
        return (Device)this.restTemplate.postForEntity(this.baseURL + "/api/customer/{customerId}/device/{deviceId}", (Object)null, Device.class, new Object[]{customerId.toString(), deviceId.toString()}).getBody();
    }

    public void saveRelation(EntityRelation relation) {
        this.restTemplate.postForLocation(this.baseURL + "/api/relation", relation, new Object[0]);
    }

    public void deleteRelation(EntityId fromId, String relationType, RelationTypeGroup relationTypeGroup, EntityId toId) {
        Map<String, String> params = new HashMap();
        params.put("fromId", fromId.getId().toString());
        params.put("fromType", fromId.getEntityType().name());
        params.put("relationType", relationType);
        params.put("relationTypeGroup", relationTypeGroup.name());
        params.put("toId", toId.getId().toString());
        params.put("toType", toId.getEntityType().name());
        this.restTemplate.delete(this.baseURL + "/api/relation?fromId={fromId}&fromType={fromType}&relationType={relationType}&relationTypeGroup={relationTypeGroup}&toId={toId}&toType={toType}", params);
    }

    public void deleteRelations(EntityId entityId) {
        this.restTemplate.delete(this.baseURL + "/api/relations?entityId={entityId}&entityType={entityType}", new Object[]{entityId.getId().toString(), entityId.getEntityType().name()});
    }

    public Optional<EntityRelation> getRelation(EntityId fromId, String relationType, RelationTypeGroup relationTypeGroup, EntityId toId) {
        Map<String, String> params = new HashMap();
        params.put("fromId", fromId.getId().toString());
        params.put("fromType", fromId.getEntityType().name());
        params.put("relationType", relationType);
        params.put("relationTypeGroup", relationTypeGroup.name());
        params.put("toId", toId.getId().toString());
        params.put("toType", toId.getEntityType().name());

        try {
            ResponseEntity<EntityRelation> entityRelation = this.restTemplate.getForEntity(this.baseURL + "/api/relation?fromId={fromId}&fromType={fromType}&relationType={relationType}&relationTypeGroup={relationTypeGroup}&toId={toId}&toType={toType}", EntityRelation.class, params);
            return Optional.ofNullable(entityRelation.getBody());
        } catch (HttpClientErrorException var7) {
            if (var7.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var7;
            }
        }
    }

    public List<EntityRelation> findByFrom(EntityId fromId, RelationTypeGroup relationTypeGroup) {
        Map<String, String> params = new HashMap();
        params.put("fromId", fromId.getId().toString());
        params.put("fromType", fromId.getEntityType().name());
        params.put("relationTypeGroup", relationTypeGroup.name());
        return (List)this.restTemplate.exchange(this.baseURL + "/api/relations?fromId={fromId}&fromType={fromType}&relationTypeGroup={relationTypeGroup}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntityRelation>>() {
        }, params).getBody();
    }

    public List<EntityRelationInfo> findInfoByFrom(EntityId fromId, RelationTypeGroup relationTypeGroup) {
        Map<String, String> params = new HashMap();
        params.put("fromId", fromId.getId().toString());
        params.put("fromType", fromId.getEntityType().name());
        params.put("relationTypeGroup", relationTypeGroup.name());
        return (List)this.restTemplate.exchange(this.baseURL + "/api/relations/info?fromId={fromId}&fromType={fromType}&relationTypeGroup={relationTypeGroup}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntityRelationInfo>>() {
        }, params).getBody();
    }

    public List<EntityRelation> findByFrom(EntityId fromId, String relationType, RelationTypeGroup relationTypeGroup) {
        Map<String, String> params = new HashMap();
        params.put("fromId", fromId.getId().toString());
        params.put("fromType", fromId.getEntityType().name());
        params.put("relationType", relationType);
        params.put("relationTypeGroup", relationTypeGroup.name());
        return (List)this.restTemplate.exchange(this.baseURL + "/api/relations?fromId={fromId}&fromType={fromType}&relationType={relationType}&relationTypeGroup={relationTypeGroup}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntityRelation>>() {
        }, params).getBody();
    }

    public List<EntityRelation> findByTo(EntityId toId, RelationTypeGroup relationTypeGroup) {
        Map<String, String> params = new HashMap();
        params.put("toId", toId.getId().toString());
        params.put("toType", toId.getEntityType().name());
        params.put("relationTypeGroup", relationTypeGroup.name());
        return (List)this.restTemplate.exchange(this.baseURL + "/api/relations?toId={toId}&toType={toType}&relationTypeGroup={relationTypeGroup}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntityRelation>>() {
        }, params).getBody();
    }

    public List<EntityRelationInfo> findInfoByTo(EntityId toId, RelationTypeGroup relationTypeGroup) {
        Map<String, String> params = new HashMap();
        params.put("toId", toId.getId().toString());
        params.put("toType", toId.getEntityType().name());
        params.put("relationTypeGroup", relationTypeGroup.name());
        return (List)this.restTemplate.exchange(this.baseURL + "/api/relations?toId={toId}&toType={toType}&relationTypeGroup={relationTypeGroup}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntityRelationInfo>>() {
        }, params).getBody();
    }

    public List<EntityRelation> findByTo(EntityId toId, String relationType, RelationTypeGroup relationTypeGroup) {
        Map<String, String> params = new HashMap();
        params.put("toId", toId.getId().toString());
        params.put("toType", toId.getEntityType().name());
        params.put("relationType", relationType);
        params.put("relationTypeGroup", relationTypeGroup.name());
        return (List)this.restTemplate.exchange(this.baseURL + "/api/relations?toId={toId}&toType={toType}&relationType={relationType}&relationTypeGroup={relationTypeGroup}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntityRelation>>() {
        }, params).getBody();
    }

    public List<EntityRelation> findByQuery(EntityRelationsQuery query) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/relations", HttpMethod.POST, new HttpEntity(query), new ParameterizedTypeReference<List<EntityRelation>>() {
        }, new Object[0]).getBody();
    }

    public List<EntityRelationInfo> findInfoByQuery(EntityRelationsQuery query) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/relations", HttpMethod.POST, new HttpEntity(query), new ParameterizedTypeReference<List<EntityRelationInfo>>() {
        }, new Object[0]).getBody();
    }

    /** @deprecated */
    @Deprecated
    public EntityRelation makeRelation(String relationType, EntityId idFrom, EntityId idTo) {
        EntityRelation relation = new EntityRelation();
        relation.setFrom(idFrom);
        relation.setTo(idTo);
        relation.setType(relationType);
        return (EntityRelation)this.restTemplate.postForEntity(this.baseURL + "/api/relation", relation, EntityRelation.class, new Object[0]).getBody();
    }

    public Optional<EntityView> getEntityViewById(EntityViewId entityViewId) {
        try {
            ResponseEntity<EntityView> entityView = this.restTemplate.getForEntity(this.baseURL + "/api/entityView/{entityViewId}", EntityView.class, new Object[]{entityViewId.getId()});
            return Optional.ofNullable(entityView.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public EntityView saveEntityView(EntityView entityView) {
        return (EntityView)this.restTemplate.postForEntity(this.baseURL + "/api/entityView", entityView, EntityView.class, new Object[0]).getBody();
    }

    public void deleteEntityView(EntityViewId entityViewId) {
        this.restTemplate.delete(this.baseURL + "/api/entityView/{entityViewId}", new Object[]{entityViewId.getId()});
    }

    public Optional<EntityView> getTenantEntityView(String entityViewName) {
        try {
            ResponseEntity<EntityView> entityView = this.restTemplate.getForEntity(this.baseURL + "/api/tenant/entityViews?entityViewName={entityViewName}", EntityView.class, new Object[]{entityViewName});
            return Optional.ofNullable(entityView.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<EntityView> assignEntityViewToCustomer(CustomerId customerId, EntityViewId entityViewId) {
        try {
            ResponseEntity<EntityView> entityView = this.restTemplate.postForEntity(this.baseURL + "/api/customer/{customerId}/entityView/{entityViewId}", (Object)null, EntityView.class, new Object[]{customerId.getId(), entityViewId.getId()});
            return Optional.ofNullable(entityView.getBody());
        } catch (HttpClientErrorException var4) {
            if (var4.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var4;
            }
        }
    }

    public Optional<EntityView> unassignEntityViewFromCustomer(EntityViewId entityViewId) {
        try {
            ResponseEntity<EntityView> entityView = this.restTemplate.exchange(this.baseURL + "/api/customer/entityView/{entityViewId}", HttpMethod.DELETE, HttpEntity.EMPTY, EntityView.class, new Object[]{entityViewId.getId()});
            return Optional.ofNullable(entityView.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public PageData<EntityView> getCustomerEntityViews(CustomerId customerId, String entityViewType, PageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("customerId", customerId.getId().toString());
        params.put("type", entityViewType);
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/customer/{customerId}/entityViews?type={type}&" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<EntityView>>() {
        }, params).getBody();
    }

    public PageData<EntityView> getTenantEntityViews(String entityViewType, PageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("type", entityViewType);
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/tenant/entityViews?type={type}&" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<EntityView>>() {
        }, params).getBody();
    }

    public List<EntityView> findByQuery(EntityViewSearchQuery query) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/entityViews", HttpMethod.POST, new HttpEntity(query), new ParameterizedTypeReference<List<EntityView>>() {
        }, new Object[0]).getBody();
    }

    public List<EntitySubtype> getEntityViewTypes() {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/entityView/types", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<EntitySubtype>>() {
        }, new Object[0]).getBody();
    }

    public Optional<EntityView> assignEntityViewToPublicCustomer(EntityViewId entityViewId) {
        try {
            ResponseEntity<EntityView> entityView = this.restTemplate.postForEntity(this.baseURL + "/api/customer/public/entityView/{entityViewId}", (Object)null, EntityView.class, new Object[]{entityViewId.getId()});
            return Optional.ofNullable(entityView.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public PageData<Event> getEvents(EntityId entityId, String eventType, TenantId tenantId, TimePageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("entityType", entityId.getEntityType().name());
        params.put("entityId", entityId.getId().toString());
        params.put("eventType", eventType);
        params.put("tenantId", tenantId.getId().toString());
        this.addTimePageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/events/{entityType}/{entityId}/{eventType}?tenantId={tenantId}&" + this.getTimeUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<Event>>() {
        }, params).getBody();
    }

    public PageData<Event> getEvents(EntityId entityId, TenantId tenantId, TimePageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("entityType", entityId.getEntityType().name());
        params.put("entityId", entityId.getId().toString());
        params.put("tenantId", tenantId.getId().toString());
        this.addTimePageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/events/{entityType}/{entityId}?tenantId={tenantId}&" + this.getTimeUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<Event>>() {
        }, params).getBody();
    }

    public void handleOneWayDeviceRPCRequest(DeviceId deviceId, JsonNode requestBody) {
        this.restTemplate.postForLocation(this.baseURL + "/api/plugins/rpc/oneway/{deviceId}", requestBody, new Object[]{deviceId.getId()});
    }

    public JsonNode handleTwoWayDeviceRPCRequest(DeviceId deviceId, JsonNode requestBody) {
        return (JsonNode)this.restTemplate.exchange(this.baseURL + "/api/plugins/rpc/twoway/{deviceId}", HttpMethod.POST, new HttpEntity(requestBody), new ParameterizedTypeReference<JsonNode>() {
        }, new Object[]{deviceId.getId()}).getBody();
    }

    public Optional<RuleChain> getRuleChainById(RuleChainId ruleChainId) {
        try {
            ResponseEntity<RuleChain> ruleChain = this.restTemplate.getForEntity(this.baseURL + "/api/ruleChain/{ruleChainId}", RuleChain.class, new Object[]{ruleChainId.getId()});
            return Optional.ofNullable(ruleChain.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<RuleChainMetaData> getRuleChainMetaData(RuleChainId ruleChainId) {
        try {
            ResponseEntity<RuleChainMetaData> ruleChainMetaData = this.restTemplate.getForEntity(this.baseURL + "/api/ruleChain/{ruleChainId}/metadata", RuleChainMetaData.class, new Object[]{ruleChainId.getId()});
            return Optional.ofNullable(ruleChainMetaData.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public RuleChain saveRuleChain(RuleChain ruleChain) {
        return (RuleChain)this.restTemplate.postForEntity(this.baseURL + "/api/ruleChain", ruleChain, RuleChain.class, new Object[0]).getBody();
    }

    public Optional<RuleChain> setRootRuleChain(RuleChainId ruleChainId) {
        try {
            ResponseEntity<RuleChain> ruleChain = this.restTemplate.postForEntity(this.baseURL + "/api/ruleChain/{ruleChainId}/root", (Object)null, RuleChain.class, new Object[]{ruleChainId.getId()});
            return Optional.ofNullable(ruleChain.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public RuleChainMetaData saveRuleChainMetaData(RuleChainMetaData ruleChainMetaData) {
        return (RuleChainMetaData)this.restTemplate.postForEntity(this.baseURL + "/api/ruleChain/metadata", ruleChainMetaData, RuleChainMetaData.class, new Object[0]).getBody();
    }

    public PageData<RuleChain> getRuleChains(PageLink pageLink) {
        Map<String, String> params = new HashMap();
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/ruleChains?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<RuleChain>>() {
        }, params).getBody();
    }

    public void deleteRuleChain(RuleChainId ruleChainId) {
        this.restTemplate.delete(this.baseURL + "/api/ruleChain/{ruleChainId}", new Object[]{ruleChainId.getId()});
    }

    public Optional<JsonNode> getLatestRuleNodeDebugInput(RuleNodeId ruleNodeId) {
        try {
            ResponseEntity<JsonNode> jsonNode = this.restTemplate.getForEntity(this.baseURL + "/api/ruleNode/{ruleNodeId}/debugIn", JsonNode.class, new Object[]{ruleNodeId.getId()});
            return Optional.ofNullable(jsonNode.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Optional<JsonNode> testScript(JsonNode inputParams) {
        try {
            ResponseEntity<JsonNode> jsonNode = this.restTemplate.postForEntity(this.baseURL + "/api/ruleChain/testScript", inputParams, JsonNode.class, new Object[0]);
            return Optional.ofNullable(jsonNode.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public List<String> getAttributeKeys(EntityId entityId) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/keys/attributes", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<String>>() {
        }, new Object[]{entityId.getEntityType().name(), entityId.getId().toString()}).getBody();
    }

    public List<String> getAttributeKeysByScope(EntityId entityId, String scope) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/keys/attributes/{scope}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<String>>() {
        }, new Object[]{entityId.getEntityType().name(), entityId.getId().toString(), scope}).getBody();
    }

    public List<AttributeKvEntry> getAttributeKvEntries(EntityId entityId, List<String> keys) {
        List<JsonNode> attributes = (List)this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/values/attributes?keys={keys}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<JsonNode>>() {
        }, new Object[]{entityId.getEntityType().name(), entityId.getId(), this.listToString(keys)}).getBody();
        return RestJsonConverter.toAttributes(attributes);
    }

    public Future<List<AttributeKvEntry>> getAttributeKvEntriesAsync(EntityId entityId, List<String> keys) {
        return this.service.submit(() -> {
            return this.getAttributeKvEntries(entityId, keys);
        });
    }

    public List<AttributeKvEntry> getAttributesByScope(EntityId entityId, String scope, List<String> keys) {
        List<JsonNode> attributes = (List)this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/values/attributes/{scope}?keys={keys}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<JsonNode>>() {
        }, new Object[]{entityId.getEntityType().name(), entityId.getId().toString(), scope, this.listToString(keys)}).getBody();
        return RestJsonConverter.toAttributes(attributes);
    }

    public List<String> getTimeseriesKeys(EntityId entityId) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/keys/timeseries", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<String>>() {
        }, new Object[]{entityId.getEntityType().name(), entityId.getId().toString()}).getBody();
    }

    public List<TsKvEntry> getLatestTimeseries(EntityId entityId, List<String> keys) {
        return this.getLatestTimeseries(entityId, keys, true);
    }

    public List<TsKvEntry> getLatestTimeseries(EntityId entityId, List<String> keys, boolean useStrictDataTypes) {
        Map<String, List<JsonNode>> timeseries = (Map)this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/values/timeseries?keys={keys}&useStrictDataTypes={useStrictDataTypes}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<Map<String, List<JsonNode>>>() {
        }, new Object[]{entityId.getEntityType().name(), entityId.getId().toString(), this.listToString(keys), useStrictDataTypes}).getBody();
        return RestJsonConverter.toTimeseries(timeseries);
    }

    public List<TsKvEntry> getTimeseries(EntityId entityId, List<String> keys, Long interval, Aggregation agg, TimePageLink pageLink) {
        return this.getTimeseries(entityId, keys, interval, agg, pageLink, true);
    }

    public List<TsKvEntry> getTimeseries(EntityId entityId, List<String> keys, Long interval, Aggregation agg, TimePageLink pageLink, boolean useStrictDataTypes) {
        Map<String, String> params = new HashMap();
        params.put("entityType", entityId.getEntityType().name());
        params.put("entityId", entityId.getId().toString());
        params.put("keys", this.listToString(keys));
        params.put("interval", interval == null ? "0" : interval.toString());
        params.put("agg", agg == null ? "NONE" : agg.name());
        params.put("useStrictDataTypes", Boolean.toString(useStrictDataTypes));
        this.addPageLinkToParam(params, pageLink);
        Map<String, List<JsonNode>> timeseries = (Map)this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/values/timeseries?keys={keys}&interval={interval}&agg={agg}&useStrictDataTypes={useStrictDataTypes}&" + this.getUrlParamsTs(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<Map<String, List<JsonNode>>>() {
        }, params).getBody();
        return RestJsonConverter.toTimeseries(timeseries);
    }

    public boolean saveDeviceAttributes(DeviceId deviceId, String scope, JsonNode request) {
        return this.restTemplate.postForEntity(this.baseURL + "/api/plugins/telemetry/{deviceId}/{scope}", request, Object.class, new Object[]{deviceId.getId().toString(), scope}).getStatusCode().is2xxSuccessful();
    }

    public boolean saveEntityAttributesV1(EntityId entityId, String scope, JsonNode request) {
        return this.restTemplate.postForEntity(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/{scope}", request, Object.class, new Object[]{entityId.getEntityType().name(), entityId.getId().toString(), scope}).getStatusCode().is2xxSuccessful();
    }

    public boolean saveEntityAttributesV2(EntityId entityId, String scope, JsonNode request) {
        return this.restTemplate.postForEntity(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/attributes/{scope}", request, Object.class, new Object[]{entityId.getEntityType().name(), entityId.getId().toString(), scope}).getStatusCode().is2xxSuccessful();
    }

    public boolean saveEntityTelemetry(EntityId entityId, String scope, JsonNode request) {
        return this.restTemplate.postForEntity(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/timeseries/{scope}", request, Object.class, new Object[]{entityId.getEntityType().name(), entityId.getId().toString(), scope}).getStatusCode().is2xxSuccessful();
    }

    public boolean saveEntityTelemetryWithTTL(EntityId entityId, String scope, Long ttl, JsonNode request) {
        return this.restTemplate.postForEntity(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/timeseries/{scope}/{ttl}", request, Object.class, new Object[]{entityId.getEntityType().name(), entityId.getId().toString(), scope, ttl}).getStatusCode().is2xxSuccessful();
    }

    public boolean deleteEntityTimeseries(EntityId entityId, List<String> keys, boolean deleteAllDataForKeys, Long startTs, Long endTs, boolean rewriteLatestIfDeleted) {
        Map<String, String> params = new HashMap();
        params.put("entityType", entityId.getEntityType().name());
        params.put("entityId", entityId.getId().toString());
        params.put("keys", this.listToString(keys));
        params.put("deleteAllDataForKeys", String.valueOf(deleteAllDataForKeys));
        params.put("startTs", startTs.toString());
        params.put("endTs", endTs.toString());
        params.put("rewriteLatestIfDeleted", String.valueOf(rewriteLatestIfDeleted));
        return this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/timeseries/delete?keys={keys}&deleteAllDataForKeys={deleteAllDataForKeys}&startTs={startTs}&endTs={endTs}&rewriteLatestIfDeleted={rewriteLatestIfDeleted}", HttpMethod.DELETE, HttpEntity.EMPTY, Object.class, params).getStatusCode().is2xxSuccessful();
    }

    public boolean deleteEntityAttributes(DeviceId deviceId, String scope, List<String> keys) {
        return this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{deviceId}/{scope}?keys={keys}", HttpMethod.DELETE, HttpEntity.EMPTY, Object.class, new Object[]{deviceId.getId().toString(), scope, this.listToString(keys)}).getStatusCode().is2xxSuccessful();
    }

    public boolean deleteEntityAttributes(EntityId entityId, String scope, List<String> keys) {
        return this.restTemplate.exchange(this.baseURL + "/api/plugins/telemetry/{entityType}/{entityId}/{scope}?keys={keys}", HttpMethod.DELETE, HttpEntity.EMPTY, Object.class, new Object[]{entityId.getEntityType().name(), entityId.getId().toString(), scope, this.listToString(keys)}).getStatusCode().is2xxSuccessful();
    }

    public Optional<Tenant> getTenantById(TenantId tenantId) {
        try {
            ResponseEntity<Tenant> tenant = this.restTemplate.getForEntity(this.baseURL + "/api/tenant/{tenantId}", Tenant.class, new Object[]{tenantId.getId()});
            return Optional.ofNullable(tenant.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Tenant saveTenant(Tenant tenant) {
        return (Tenant)this.restTemplate.postForEntity(this.baseURL + "/api/tenant", tenant, Tenant.class, new Object[0]).getBody();
    }

    public void deleteTenant(TenantId tenantId) {
        this.restTemplate.delete(this.baseURL + "/api/tenant/{tenantId}", new Object[]{tenantId.getId()});
    }

    public PageData<Tenant> getTenants(PageLink pageLink) {
        Map<String, String> params = new HashMap();
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/tenants?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<Tenant>>() {
        }, params).getBody();
    }

    public Optional<User> getUserById(UserId userId) {
        try {
            ResponseEntity<User> user = this.restTemplate.getForEntity(this.baseURL + "/api/user/{userId}", User.class, new Object[]{userId.getId()});
            return Optional.ofNullable(user.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public Boolean isUserTokenAccessEnabled() {
        return (Boolean)this.restTemplate.getForEntity(this.baseURL + "/api/user/tokenAccessEnabled", Boolean.class, new Object[0]).getBody();
    }

    public Optional<JsonNode> getUserToken(UserId userId) {
        try {
            ResponseEntity<JsonNode> userToken = this.restTemplate.getForEntity(this.baseURL + "/api/user/{userId}/token", JsonNode.class, new Object[]{userId.getId()});
            return Optional.ofNullable(userToken.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public User saveUser(User user, boolean sendActivationMail) {
        return (User)this.restTemplate.postForEntity(this.baseURL + "/api/user?sendActivationMail={sendActivationMail}", user, User.class, new Object[]{sendActivationMail}).getBody();
    }

    public void sendActivationEmail(String email) {
        this.restTemplate.postForLocation(this.baseURL + "/api/user/sendActivationMail?email={email}", (Object)null, new Object[]{email});
    }

    public String getActivationLink(UserId userId) {
        return (String)this.restTemplate.getForEntity(this.baseURL + "/api/user/{userId}/activationLink", String.class, new Object[]{userId.getId()}).getBody();
    }

    public void deleteUser(UserId userId) {
        this.restTemplate.delete(this.baseURL + "/api/user/{userId}", new Object[]{userId.getId()});
    }

    public PageData<User> getTenantAdmins(TenantId tenantId, PageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("tenantId", tenantId.getId().toString());
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/tenant/{tenantId}/users?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<User>>() {
        }, params).getBody();
    }

    public PageData<User> getCustomerUsers(CustomerId customerId, PageLink pageLink) {
        Map<String, String> params = new HashMap();
        params.put("customerId", customerId.getId().toString());
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/customer/{customerId}/users?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<User>>() {
        }, params).getBody();
    }

    public void setUserCredentialsEnabled(UserId userId, boolean userCredentialsEnabled) {
        this.restTemplate.postForLocation(this.baseURL + "/api/user/{userId}/userCredentialsEnabled?serCredentialsEnabled={serCredentialsEnabled}", (Object)null, new Object[]{userId.getId(), userCredentialsEnabled});
    }

    public Optional<WidgetsBundle> getWidgetsBundleById(WidgetsBundleId widgetsBundleId) {
        try {
            ResponseEntity<WidgetsBundle> widgetsBundle = this.restTemplate.getForEntity(this.baseURL + "/api/widgetsBundle/{widgetsBundleId}", WidgetsBundle.class, new Object[]{widgetsBundleId.getId()});
            return Optional.ofNullable(widgetsBundle.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public WidgetsBundle saveWidgetsBundle(WidgetsBundle widgetsBundle) {
        return (WidgetsBundle)this.restTemplate.postForEntity(this.baseURL + "/api/widgetsBundle", widgetsBundle, WidgetsBundle.class, new Object[0]).getBody();
    }

    public void deleteWidgetsBundle(WidgetsBundleId widgetsBundleId) {
        this.restTemplate.delete(this.baseURL + "/api/widgetsBundle/{widgetsBundleId}", new Object[]{widgetsBundleId.getId()});
    }

    public PageData<WidgetsBundle> getWidgetsBundles(PageLink pageLink) {
        Map<String, String> params = new HashMap();
        this.addPageLinkToParam(params, pageLink);
        return (PageData)this.restTemplate.exchange(this.baseURL + "/api/widgetsBundles?" + this.getUrlParams(pageLink), HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<PageData<WidgetsBundle>>() {
        }, params).getBody();
    }

    public List<WidgetsBundle> getWidgetsBundles() {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/widgetsBundles", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<WidgetsBundle>>() {
        }, new Object[0]).getBody();
    }

    public Optional<WidgetType> getWidgetTypeById(WidgetTypeId widgetTypeId) {
        try {
            ResponseEntity<WidgetType> widgetType = this.restTemplate.getForEntity(this.baseURL + "/api/widgetType/{widgetTypeId}", WidgetType.class, new Object[]{widgetTypeId.getId()});
            return Optional.ofNullable(widgetType.getBody());
        } catch (HttpClientErrorException var3) {
            if (var3.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var3;
            }
        }
    }

    public WidgetType saveWidgetType(WidgetType widgetType) {
        return (WidgetType)this.restTemplate.postForEntity(this.baseURL + "/api/widgetType", widgetType, WidgetType.class, new Object[0]).getBody();
    }

    public void deleteWidgetType(WidgetTypeId widgetTypeId) {
        this.restTemplate.delete(this.baseURL + "/api/widgetType/{widgetTypeId}", new Object[]{widgetTypeId.getId()});
    }

    public List<WidgetType> getBundleWidgetTypes(boolean isSystem, String bundleAlias) {
        return (List)this.restTemplate.exchange(this.baseURL + "/api/widgetTypes?isSystem={isSystem}&bundleAlias={bundleAlias}", HttpMethod.GET, HttpEntity.EMPTY, new ParameterizedTypeReference<List<WidgetType>>() {
        }, new Object[]{isSystem, bundleAlias}).getBody();
    }

    public Optional<WidgetType> getWidgetType(boolean isSystem, String bundleAlias, String alias) {
        try {
            ResponseEntity<WidgetType> widgetType = this.restTemplate.getForEntity(this.baseURL + "/api/widgetType?isSystem={isSystem}&bundleAlias={bundleAlias}&alias={alias}", WidgetType.class, new Object[]{isSystem, bundleAlias, alias});
            return Optional.ofNullable(widgetType.getBody());
        } catch (HttpClientErrorException var5) {
            if (var5.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var5;
            }
        }
    }

    /** @deprecated */
    @Deprecated
    public Optional<JsonNode> getAttributes(String accessToken, String clientKeys, String sharedKeys) {
        Map<String, String> params = new HashMap();
        params.put("accessToken", accessToken);
        params.put("clientKeys", clientKeys);
        params.put("sharedKeys", sharedKeys);

        try {
            ResponseEntity<JsonNode> telemetryEntity = this.restTemplate.getForEntity(this.baseURL + "/api/v1/{accessToken}/attributes?clientKeys={clientKeys}&sharedKeys={sharedKeys}", JsonNode.class, params);
            return Optional.of(telemetryEntity.getBody());
        } catch (HttpClientErrorException var6) {
            if (var6.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            } else {
                throw var6;
            }
        }
    }

    private String getTimeUrlParams(TimePageLink pageLink) {
        return this.getUrlParams(pageLink);
    }

    private String getUrlParams(TimePageLink pageLink) {
        return this.getUrlParams(pageLink, "startTime", "endTime");
    }

    private String getUrlParamsTs(TimePageLink pageLink) {
        return this.getUrlParams(pageLink, "startTs", "endTs");
    }

    private String getUrlParams(TimePageLink pageLink, String startTime, String endTime) {
        String urlParams = "limit={limit}&ascOrder={ascOrder}";
        if (pageLink.getStartTime() != null) {
            urlParams = urlParams + "&" + startTime + "={startTime}";
        }

        if (pageLink.getEndTime() != null) {
            urlParams = urlParams + "&" + endTime + "={endTime}";
        }

        return urlParams;
    }

    private String getUrlParams(PageLink pageLink) {
        String urlParams = "pageSize={pageSize}&page={page}";
        if (!StringUtils.isEmpty(pageLink.getTextSearch())) {
            urlParams = urlParams + "&textSearch={textSearch}";
        }

        if (pageLink.getSortOrder() != null) {
            urlParams = urlParams + "&sortProperty={sortProperty}&sortOrder={sortOrder}";
        }

        return urlParams;
    }

    private void addTimePageLinkToParam(Map<String, String> params, TimePageLink pageLink) {
        this.addPageLinkToParam(params, pageLink);
        if (pageLink.getStartTime() != null) {
            params.put("startTime", String.valueOf(pageLink.getStartTime()));
        }

        if (pageLink.getEndTime() != null) {
            params.put("endTime", String.valueOf(pageLink.getEndTime()));
        }

    }

    private void addPageLinkToParam(Map<String, String> params, PageLink pageLink) {
        params.put("pageSize", String.valueOf(pageLink.getPageSize()));
        params.put("page", String.valueOf(pageLink.getPage()));
        if (!StringUtils.isEmpty(pageLink.getTextSearch())) {
            params.put("textSearch", pageLink.getTextSearch());
        }

        if (pageLink.getSortOrder() != null) {
            params.put("sortProperty", pageLink.getSortOrder().getProperty());
            params.put("sortOrder", pageLink.getSortOrder().getDirection().name());
        }

    }

    private String listToString(List<String> list) {
        return String.join(",", list);
    }

    private String listIdsToString(List<? extends EntityId> list) {
        return this.listToString((List)list.stream().map((id) -> {
            return id.getId().toString();
        }).collect(Collectors.toList()));
    }

    private String listEnumToString(List<? extends Enum> list) {
        return this.listToString((List)list.stream().map(Enum::name).collect(Collectors.toList()));
    }

    public void close() {
        if (this.service != null) {
            this.service.shutdown();
        }

    }
}
