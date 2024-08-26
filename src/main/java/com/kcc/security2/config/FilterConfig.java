package com.kcc.security2.config;

import com.kcc.security2.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    // spring frame work에 등록한것이다.
    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {

        FilterRegistrationBean<MyFilter2> bean =
                new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*");
        bean.setOrder(0);
        return bean;
    }
}
