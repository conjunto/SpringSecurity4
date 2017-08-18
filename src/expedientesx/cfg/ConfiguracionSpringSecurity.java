package expedientesx.cfg;
import java.util.Arrays;
import java.util.Properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import expedientesx.util.HorarioVoter;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(securedEnabled = true)
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled=true, prePostEnabled=true)
public class ConfiguracionSpringSecurity extends WebSecurityConfigurerAdapter {

//Version 1
//	@Autowired
//	public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication().withUser("Fernando").password("1234").roles("AGENTE");
//		auth.inMemoryAuthentication().withUser("Mulder").password("fox").roles("AGENTE_ESPECIAL");
//		auth.inMemoryAuthentication().withUser("Scully").password("dana").roles("AGENTE_ESPECIAL");
//		auth.inMemoryAuthentication().withUser("Skinner").password("walter").roles("DIRECTOR");
//	}

//Version 3
//	@Autowired
//	public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
//		auth.userDetailsService(userDetailsService());
//	}	

//Version 3
//	public UserDetailsService userDetailsService(){
//        Properties usuarios = new Properties();
//		usuarios.put("Fernando","1234,ROLE_AGENTE,enabled");
//		usuarios.put("Mulder"  ,"fox,ROLE_AGENTE_ESPECIAL,enabled");
//		usuarios.put("Scully"  ,"dana,ROLE_AGENTE_ESPECIAL,enabled");
//		usuarios.put("Skinner" ,"walter,ROLE_DIRECTOR,enabled");
//        
//		return new InMemoryUserDetailsManager(usuarios);
//	}
	@Bean
	public UnanimousBased accessDecisionManager() throws Exception {
		UnanimousBased unanimousBased = new UnanimousBased(
				Arrays.asList(new AuthenticatedVoter(), 
						  new WebExpressionVoter(), 
						  new RoleVoter(),
						  new HorarioVoter() ) );
		unanimousBased.setAllowIfAllAbstainDecisions(false);
		unanimousBased.afterPropertiesSet();

		return unanimousBased;
	}
	
	@Bean
	public PasswordEncoder passwordEncoder(){
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
	}
	
	@Autowired
	public void configureGlobalSecurity(AuthenticationManagerBuilder auth, PasswordEncoder pe) throws Exception {
		auth.userDetailsService(userDetailsService()).passwordEncoder(pe);
	}	
	
	public UserDetailsService userDetailsService(){
        Properties usuarios = new Properties();
		usuarios.put("Fernando","$2a$10$SMPYtil7Hs2.cV7nrMjrM.dRAkuoLdYM8NdVrF.GeHfs/MrzcQ/zi,ROLE_AGENTE,enabled");
		usuarios.put("Mulder"  ,"$2a$10$M2JRRHUHTfv4uMR4NWmCLebk1r9DyWSwCMZmuq4LKbImOkfhGFAIa,ROLE_AGENTE_ESPECIAL,enabled");
		usuarios.put("Scully"  ,"$2a$10$cbF5xp0grCOGcI6jZvPhA.asgmILATW1hNbM2MEqGJEFnRhhQd3ba,ROLE_AGENTE_ESPECIAL,enabled");
		usuarios.put("Skinner" ,"$2a$10$ZFtPIULMcxPe3r/5VunbVujMD7Lw8hkqAmJlxmK5Y1TK3L1bf8ULG,ROLE_DIRECTOR,enabled");
        
		return new InMemoryUserDetailsManager(usuarios);
	}	
			
	@Override
	protected void configure(HttpSecurity http) throws Exception {
//Version 1
//		http.authorizeRequests().
//			antMatchers("/**").
//				access("hasRole('AGENTE_ESPECIAL')").
//			and().formLogin(); //Esto crea una pantalla de login automaticamente

		http.formLogin().loginPage("/paginas/nuestro-login.jsp").failureUrl("/paginas/nuestro-login.jsp?login_error");
		http.logout().logoutSuccessUrl("/paginas/desconectado.jsp").deleteCookies("JSESSIONID");
		//Version 2
		//http.authorizeRequests().antMatchers("/**").access("hasRole('AGENTE_ESPECIAL')");

		//Penultima version
//		http.authorizeRequests()
//			.antMatchers("/paginas/*").permitAll()
//			.antMatchers("/css/*").permitAll()
//			.antMatchers("/imagenes/*").permitAll()
//			.antMatchers("/**").access("hasRole('AGENTE_ESPECIAL')");

		http
		.authorizeRequests()
			.accessDecisionManager(accessDecisionManager())
			.antMatchers("/paginas/*").permitAll()
			.antMatchers("/css/*").permitAll()
			.antMatchers("/imagenes/*").permitAll()
			.antMatchers("/**").access("isAuthenticated()");
		
		//Punto 16. CSRF
		http.csrf().disable();
		
		//Punto 8.    Añadir funcionalidad "Remember Me"
		http.rememberMe() 
		.rememberMeParameter("remember-me-param")
		.rememberMeCookieName("my-remember-me")
		.tokenValiditySeconds(86400);
		
		//Punto 9.    Seguridad en el canal de transporte (HTTPS) - Configurar restricciones y puertos
		http
		.requiresChannel()
		.anyRequest()
		.requiresSecure()
		.and()
		.portMapper().http(8080).mapsTo(8443);
		
		//Punto 11.    Control de la expiración de sesiones
		http
		.logout()
			.logoutSuccessUrl("/paginas/desconectado.jsp")
			.deleteCookies("JSESSIONID");

		//Punto 12 (Cont).    Control de la concurrencia de sesiones (Funciona junto con: servletContext.addListener(new HttpSessionEventPublisher());)
		http
			.sessionManagement()
			.invalidSessionUrl("/paginas/sesion-expirada.jsp")
			.maximumSessions(1)
			.maxSessionsPreventsLogin(true);
		
		http
		.exceptionHandling()
		.accessDeniedPage("/paginas/acceso-denegado.jsp");
	}
}