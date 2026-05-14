package com.packtpub.springsecurity.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
         UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("admin")
                .roles("ADMIN")
                .build();

        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("user1@example.com")
                .password("user1")
                .roles("USER")
                .build();

        UserDetails admin1 = User.withDefaultPasswordEncoder()
                .username("admin1@example.com")
                .password("admin1")
                .roles("USER", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin, user1, admin1);

    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/resources/**").permitAll()
                        .requestMatchers("/webjars/**").permitAll()
                        .requestMatchers("/").hasAnyRole("ANONYMOUS", "USER")
                        .requestMatchers("/login/*").hasAnyRole("ANONYMOUS", "USER")
                        .requestMatchers("/logout/*").hasAnyRole("ANONYMOUS", "USER")
                        .requestMatchers("/admin/*").hasRole("ADMIN")
                        .requestMatchers("/events/").hasRole("ADMIN")
                        .requestMatchers("/**").hasRole("USER"))
                //.formLogin(Customizer.withDefaults())
                .formLogin(form -> form
                        .loginPage("/login/form")
                        .loginProcessingUrl("/login")
                        .failureUrl("/login/form?error")
                        .usernameParameter("username")
                        .passwordParameter("password"))
                .logout(form -> form
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login/form?logout")
                )
                .csrf(AbstractHttpConfigurer::disable);

        http.headers(headers ->
                headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

//        http
//                .authorizeHttpRequests( authz -> authz
//                        .requestMatchers("/**")
//                        .hasRole("USER")
//                )
//                .formLogin(form -> form
//                        .loginPage("/login/form")
//                        .loginProcessingUrl("/login")
//                        .failureUrl("/login/form?error")
//                        .usernameParameter("username")
//                        .passwordParameter("password");


        return http.build();
    }
}
