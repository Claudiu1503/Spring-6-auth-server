package guru.springframework.spring6authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration // Marcheaza aceasta clasa ca fiind o configuratie Spring
public class SecurityConfig {

    @Bean // Defineste un bean gestionat de Spring pentru filtrul de securitate
    @Order(1) // Seteaza ordinea de aplicare a acestui lant de filtre (primul care se aplica)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        // Aplica configuratia implicita pentru un server de autorizare OAuth2
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Configureaza serverul de autorizare pentru a suporta OpenID Connect (OIDC)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Activeaza OpenID Connect 1.0

        http
                // Configureaza tratamentul pentru exceptiile de autentificare
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                // Redirectioneaza utilizatorul catre pagina de login daca nu este autentificat
                                new LoginUrlAuthenticationEntryPoint("/login"))
                )
                // Configureaza serverul de resurse OAuth2 pentru a accepta si valida tokenuri JWT
                .oauth2ResourceServer((oauth2) -> oauth2
                        .jwt(Customizer.withDefaults())); // Accepta tokenuri JWT pentru accesul la resurse

        // Construieste si returneaza configuratia filtrului de securitate pentru serverul de autorizare
        return http.build();
    }

    @Bean // Defineste un alt bean pentru al doilea lant de filtre de securitate
    @Order(2) // Seteaza ordinea de aplicare a acestui lant de filtre (al doilea in ordine)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {

        http
                // Configureaza permisiunile pentru toate cererile HTTP
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated() // Orice cerere trebuie sa fie autentificata
                )
                // Activeaza login-ul printr-un formular web implicit
                .formLogin(Customizer.withDefaults()); // Foloseste configuratia implicita pentru form login

        // Construieste si returneaza configuratia filtrului de securitate pentru aplicatia web
        return http.build();
    }

    @Bean // Defineste un bean pentru UserDetailsService, care va fi gestionat de Spring
    public UserDetailsService userDetailsService() {

        // Creeaza un obiect UserDetails folosind un constructor care seteaza un encoder de parola implicit
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")          // Seteaza numele de utilizator
                .password("password")      // Seteaza parola
                .roles("USER")             // Atribuie rolul "USER"
                .build();                  // Construieste obiectul UserDetails

        // Returneaza o instanta de InMemoryUserDetailsManager care gestioneaza utilizatorii in memorie
        // si foloseste obiectul userDetails creat mai sus
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean // Defineste un bean pentru RegisteredClientRepository, care va fi gestionat de Spring
    public RegisteredClientRepository registeredClientRepository() {

        // Creeaza un client OAuth2 folosind un UUID pentru identificarea acestuia
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client") // Seteaza un ID unic pentru client (nume de client)
                .clientSecret("{noop}secret") // Seteaza parola secreta a clientului, folosind encoderul "noop" (fara encoding)

                // Specifica metoda de autentificare pentru client. In acest caz, CLIENT_SECRET_BASIC
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                // Specifica tipurile de granturi de autorizare acceptate de client
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Suporta grantul "Authorization Code"
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)      // Suporta grantul "Refresh Token"
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // Suporta grantul "Client Credentials"

                // Seteaza URL-urile de redirectionare ale clientului
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc") // URL pentru redirectionare dupa autorizare
                .redirectUri("http://127.0.0.1:8080/authorized") // Un alt URL pentru redirectionare dupa autorizare

                // Defineste scope-urile clientului (resursele la care poate accesa)
                .scope(OidcScopes.OPENID) // Scope pentru OpenID Connect (OIDC)
                .scope(OidcScopes.PROFILE) // Scope pentru profilul utilizatorului
                .scope("message.read")     // Scope personalizat pentru citirea mesajelor
                .scope("message.write")    // Scope personalizat pentru scrierea mesajelor

                // Configureaza setarile clientului, specificand ca este necesar consimtamantul utilizatorului pentru autorizare
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())

                // Construieste obiectul RegisteredClient cu toate setarile de mai sus
                .build();

        // Returneaza un repository in-memory care stocheaza clientul inregistrat
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean // Declara aceasta metoda ca un bean Spring
    public JWKSource<SecurityContext> jwkSource() {
        // Genereaza o pereche de chei RSA (publica si privata)
        KeyPair keyPair = generateRsaKey();
        // Extrage cheia publica din perechea de chei si o castreaza la tipul RSAPublicKey
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        // Extrage cheia privata din perechea de chei si o castreaza la tipul RSAPrivateKey
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // Construieste un obiect RSAKey folosind cheia publica si privata

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey) // Adauga cheia privata la RSAKey
                .keyID(UUID.randomUUID().toString()) // Seteaza un ID unic pentru aceasta cheie (folosind UUID)
                .build(); // Construieste obiectul RSAKey
        // Creeaza un set de chei JWK (JWKSet) care contine cheia RSA
        JWKSet jwkSet = new JWKSet(rsaKey);
        // Returneaza o sursa de chei JWK imutabila (ImmutableJWKSet) care contine setul de chei creat anterior
        return new ImmutableJWKSet<>(jwkSet);
    }


    private static KeyPair generateRsaKey() {
        KeyPair keyPair; // Declara o variabila pentru a stoca perechea de chei
        try {
            // Creeaza un generator de perechi de chei RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            // Initializeaza generatorul de chei cu o lungime de 2048 de biti (securitate standard)
            keyPairGenerator.initialize(2048);
            // Genereaza si returneaza perechea de chei
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) { // Prinde orice exceptie care ar putea aparea in timpul generarii cheilor
            // Arunca o exceptie runtime daca ceva nu functioneaza corect
            throw new IllegalStateException(ex);
        }

        return keyPair; // Returneaza perechea de chei generata
    }

    @Bean // Declara aceasta metoda ca un bean Spring
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        // Returneaza un JwtDecoder folosind configuratia standard din OAuth2AuthorizationServerConfiguration
        // si sursa de chei JWK transmisa ca parametru
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
    @Bean // Declara metoda ca un bean Spring
    public AuthorizationServerSettings authorizationServerSettings() {
        // Construieste un obiect de tip AuthorizationServerSettings cu setarile implicite
        return AuthorizationServerSettings.builder().build();
    }


}
