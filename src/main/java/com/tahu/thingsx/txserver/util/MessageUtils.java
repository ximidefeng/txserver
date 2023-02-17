package com.tahu.thingsx.txserver.util;

import org.springframework.context.MessageSource;

import java.util.Locale;

public class MessageUtils {

    public static String message(String code, Object... args) {

        MessageSource messageSource = SpringUtils.getBean(MessageSource.class);
        //LocaleContextHolder.getLocale() 中文：Locale.SIMPLIFIED_CHINESE 英文： Locale.US
        return messageSource.getMessage(code, args, Locale.US);
    }


    public static String message(String code,String lang, Object... args) {
        //LocaleContextHolder.getLocale() 中文：Locale.SIMPLIFIED_CHINESE 英文： Locale.US
        MessageSource messageSource = SpringUtils.getBean(MessageSource.class);
        if("zh_CN".equals(lang)){
            return messageSource.getMessage(code, args, Locale.CHINA);
        }else {
            return messageSource.getMessage(code, args, Locale.US);
        }

    }
}
