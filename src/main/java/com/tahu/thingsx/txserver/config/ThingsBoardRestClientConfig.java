package com.tahu.thingsx.txserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thingsboard.rest.client.RestClient;

@Configuration
public class ThingsBoardRestClientConfig {

    @Value("${tb.url}")
    private String url;

    @Value("${tb.username}")
    public String userName;

    @Value("${tb.password}")
    public String passWord;

    @Bean
    public TXRestClient restClient(){
        return  new TXRestClient(url);
    }
}
