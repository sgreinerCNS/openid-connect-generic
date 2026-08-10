<?php
/**
 * Plugin OIDC/oAuth client class.
 *
 * @package   OpenID_Connect_Generic
 * @category  Authentication
 * @author    Jonathan Daggerhart <jonathan@daggerhart.com>
 * @copyright 2015-2020 daggerhart
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Generic_Client class.
 *
 * Plugin OIDC/oAuth client class.
 *
 * @package  OpenID_Connect_Generic
 * @category Authentication
 */
class OpenID_Connect_Generic_Client {

	/**
	 * The OIDC/oAuth client ID.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::client_id
	 *
	 * @var string
	 */
	private $client_id;

	/**
	 * The OIDC/oAuth client secret.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::client_secret
	 *
	 * @var string
	 */
	private $client_secret;

	/**
	 * The OIDC/oAuth scopes.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::scope
	 *
	 * @var string
	 */
	private $scope;

	/**
	 * The OIDC/oAuth authorization endpoint URL.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::endpoint_login
	 *
	 * @var string
	 */
	private $endpoint_login;

	/**
	 * The OIDC/oAuth User Information endpoint URL.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::endpoint_userinfo
	 *
	 * @var string
	 */
	private $endpoint_userinfo;

	/**
	 * The OIDC/oAuth token validation endpoint URL.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::endpoint_token
	 *
	 * @var string
	 */
	private $endpoint_token;

	/**
	 * The login flow "ajax" endpoint URI.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::redirect_uri
	 *
	 * @var string
	 */
	private $redirect_uri;

	/**
	 * The specifically requested authentication contract at the IDP
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::acr_values
	 *
	 * @var string
	 */
	private $acr_values;

	/**
	 * The JWKS endpoint URL for JWT signature verification.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::endpoint_jwks
	 *
	 * @var string
	 */
	private $endpoint_jwks;

	/**
	 * The issuer URL for JWT validation.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::issuer
	 *
	 * @var string
	 */
	private $issuer;

	/**
	 * The JWKS cache TTL in seconds.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::jwks_cache_ttl
	 *
	 * @var int
	 */
	private $jwks_cache_ttl;

	/**
	 * The state time limit. States are only valid for 3 minutes.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::state_time_limit
	 *
	 * @var int
	 */
	private $state_time_limit = 180;

	/**
	 * Allow HTTP requests to internal/private network endpoints.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::allow_internal_idp
	 *
	 * @var bool
	 */
	private $allow_internal_idp;

	/**
	 * Whether to protect the authorization code with PKCE.
	 *
	 * @see OpenID_Connect_Generic_Option_Settings::enable_pkce
	 *
	 * @var bool
	 */
	private $enable_pkce = true;

	/**
	 * The data stored alongside the state of the authentication flow that is
	 * currently being processed.
	 *
	 * Populated by new_state() when a flow is started, and by check_state()
	 * when an authorization response is validated.
	 *
	 * @var array<mixed>
	 */
	private $current_state = array();

	/**
	 * The logger object instance.
	 *
	 * @var OpenID_Connect_Generic_Option_Logger
	 */
	private $logger;

	/**
	 * Client constructor.
	 *
	 * @param string                               $client_id          @see OpenID_Connect_Generic_Option_Settings::client_id for description.
	 * @param string                               $client_secret      @see OpenID_Connect_Generic_Option_Settings::client_secret for description.
	 * @param string                               $scope              @see OpenID_Connect_Generic_Option_Settings::scope for description.
	 * @param string                               $endpoint_login     @see OpenID_Connect_Generic_Option_Settings::endpoint_login for description.
	 * @param string                               $endpoint_userinfo  @see OpenID_Connect_Generic_Option_Settings::endpoint_userinfo for description.
	 * @param string                               $endpoint_token     @see OpenID_Connect_Generic_Option_Settings::endpoint_token for description.
	 * @param string                               $redirect_uri       @see OpenID_Connect_Generic_Option_Settings::redirect_uri for description.
	 * @param string                               $acr_values         @see OpenID_Connect_Generic_Option_Settings::acr_values for description.
	 * @param string                               $endpoint_jwks      @see OpenID_Connect_Generic_Option_Settings::endpoint_jwks for description.
	 * @param string                               $issuer             @see OpenID_Connect_Generic_Option_Settings::issuer for description.
	 * @param int                                  $jwks_cache_ttl     @see OpenID_Connect_Generic_Option_Settings::jwks_cache_ttl for description.
	 * @param int                                  $state_time_limit   @see OpenID_Connect_Generic_Option_Settings::state_time_limit for description.
	 * @param bool                                 $allow_internal_idp @see OpenID_Connect_Generic_Option_Settings::allow_internal_idp for description.
	 * @param OpenID_Connect_Generic_Option_Logger $logger             The plugin logging object instance.
	 * @param bool                                 $enable_pkce        @see OpenID_Connect_Generic_Option_Settings::enable_pkce for description.
	 */
	public function __construct( $client_id, $client_secret, $scope, $endpoint_login, $endpoint_userinfo, $endpoint_token, $redirect_uri, $acr_values, $endpoint_jwks, $issuer, $jwks_cache_ttl, $state_time_limit, $allow_internal_idp, $logger, $enable_pkce = true ) {
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->scope = $scope;
		$this->endpoint_login = $endpoint_login;
		$this->endpoint_userinfo = $endpoint_userinfo;
		$this->endpoint_token = $endpoint_token;
		$this->redirect_uri = $redirect_uri;
		$this->acr_values = $acr_values;
		$this->endpoint_jwks = $endpoint_jwks;
		$this->issuer = $issuer;
		$this->jwks_cache_ttl = $jwks_cache_ttl;
		$this->state_time_limit = $state_time_limit;
		$this->allow_internal_idp = $allow_internal_idp;
		$this->logger = $logger;
		$this->enable_pkce = boolval( $enable_pkce );
	}

	/**
	 * Make a safe HTTP GET request with optional internal endpoint support.
	 *
	 * By default, uses wp_safe_remote_get() which blocks requests to internal/private
	 * networks (SSRF protection). If allow_internal_idp is enabled, uses wp_remote_get()
	 * to allow connections to localhost and private network identity providers.
	 *
	 * @param string $url  The URL to request.
	 * @param array  $args Optional. Request arguments.
	 *
	 * @return array|WP_Error Response array or WP_Error on failure.
	 */
	private function http_get( $url, $args = array() ) {
		if ( $this->allow_internal_idp ) {
			return wp_remote_get( $url, $args );
		}
		return wp_safe_remote_get( $url, $args );
	}

	/**
	 * Make a safe HTTP POST request with optional internal endpoint support.
	 *
	 * By default, uses wp_safe_remote_post() which blocks requests to internal/private
	 * networks (SSRF protection). If allow_internal_idp is enabled, uses wp_remote_post()
	 * to allow connections to localhost and private network identity providers.
	 *
	 * @param string $url  The URL to request.
	 * @param array  $args Optional. Request arguments.
	 *
	 * @return array|WP_Error Response array or WP_Error on failure.
	 */
	private function http_post( $url, $args = array() ) {
		if ( $this->allow_internal_idp ) {
			return wp_remote_post( $url, $args );
		}
		return wp_safe_remote_post( $url, $args );
	}

	/**
	 * Provides the configured Redirect URI supplied to the IDP.
	 *
	 * @return string
	 */
	public function get_redirect_uri() {
		return $this->redirect_uri;
	}

	/**
	 * Provide the configured IDP endpoint login URL.
	 *
	 * @return string
	 */
	public function get_endpoint_login_url() {
		return $this->endpoint_login;
	}

	/**
	 * Validate the request for login authentication
	 *
	 * @param array<string> $request       The authentication request results.
	 * @param string        $state_binding The user agent's state binding value, when available.
	 *
	 * @return array<string>|WP_Error
	 */
	public function validate_authentication_request( $request, $state_binding = '' ) {
		// Look for an existing error of some kind.
		if ( isset( $request['error'] ) ) {
			$error_code = sanitize_text_field( $request['error'] );
			$error_message = 'An unknown error occurred.';

			// Use the IDP's error description if available for better diagnostics.
			if ( ! empty( $request['error_description'] ) ) {
				$error_message = sprintf(
					'IDP error %s: %s',
					$error_code,
					sanitize_text_field( $request['error_description'] )
				);
			}

			return new WP_Error( $error_code, $error_message, $request );
		}

		// Make sure we have a legitimate authentication code and valid state.
		if ( ! isset( $request['code'] ) ) {
			return new WP_Error( 'no-code', 'No authentication code present in the request.', $request );
		}

		// Check the client request state.
		if ( ! isset( $request['state'] ) ) {
			do_action( 'openid-connect-generic-no-state-provided' );
			return new WP_Error( 'missing-state', __( 'Missing state.', 'daggerhart-openid-connect-generic' ), $request );
		}

		if ( ! $this->check_state( $request['state'], $state_binding ) ) {
			return new WP_Error( 'invalid-state', __( 'Invalid state.', 'daggerhart-openid-connect-generic' ), $request );
		}

		return $request;
	}

	/**
	 * Get the authorization code from the request
	 *
	 * @param array<string>|WP_Error $request The authentication request results.
	 *
	 * @return string|WP_Error
	 */
	public function get_authentication_code( $request ) {
		if ( ! isset( $request['code'] ) ) {
			return new WP_Error( 'missing-authentication-code', __( 'Missing authentication code.', 'daggerhart-openid-connect-generic' ), $request );
		}

		return $request['code'];
	}

	/**
	 * Using the authorization_code, request an authentication token from the IDP.
	 *
	 * @param string|WP_Error $code The authorization code.
	 *
	 * @return array<mixed>|WP_Error
	 */
	public function request_authentication_token( $code ) {

		// Add Host header - required for when the openid-connect endpoint is behind a reverse-proxy.
		$parsed_url = parse_url( $this->endpoint_token );
		$host = $parsed_url['host'];

		$request = array(
			'body' => array(
				'code'          => $code,
				'client_id'     => $this->client_id,
				'client_secret' => $this->client_secret,
				'redirect_uri'  => $this->redirect_uri,
				'grant_type'    => 'authorization_code',
				'scope'         => $this->scope,
			),
			'headers' => array( 'Host' => $host ),
		);

		if ( ! empty( $this->acr_values ) ) {
			$request['body'] += array( 'acr_values' => $this->acr_values );
		}

		/*
		 * Prove possession of the PKCE code verifier that was used to build the
		 * code challenge of this flow. Only sent when the state that was just
		 * validated actually carries a verifier. RFC 7636 section 4.5.
		 */
		if ( ! empty( $this->current_state['code_verifier'] ) ) {
			$request['body']['code_verifier'] = $this->current_state['code_verifier'];
		}

		// Allow modifications to the request.
		$request = apply_filters( 'openid-connect-generic-alter-request', $request, 'get-authentication-token' );

		// Call the server and ask for a token.
		$start_time = microtime( true );
		$response   = $this->http_post( $this->endpoint_token, $request );
		$end_time   = microtime( true );
		$this->logger->log( $this->endpoint_token, 'request_authentication_token', $end_time - $start_time );

		if ( is_wp_error( $response ) ) {
			$response->add( 'request_authentication_token', __( 'Request for authentication token failed.', 'daggerhart-openid-connect-generic' ) );
		}

		return $response;
	}

	/**
	 * Using the refresh token, request new tokens from the idp
	 *
	 * @param string $refresh_token The refresh token previously obtained from token response.
	 *
	 * @return array|WP_Error
	 */
	public function request_new_tokens( $refresh_token ) {
		$request = array(
			'body' => array(
				'refresh_token' => $refresh_token,
				'client_id'     => $this->client_id,
				'client_secret' => $this->client_secret,
				'grant_type'    => 'refresh_token',
			),
		);

		// Allow modifications to the request.
		$request = apply_filters( 'openid-connect-generic-alter-request', $request, 'refresh-token' );

		// Call the server and ask for new tokens.
		$start_time = microtime( true );
		$response   = $this->http_post( $this->endpoint_token, $request );
		$end_time   = microtime( true );
		$this->logger->log( $this->endpoint_token, 'request_new_tokens', $end_time - $start_time );

		if ( is_wp_error( $response ) ) {
			$response->add( 'refresh_token', __( 'Refresh token failed.', 'daggerhart-openid-connect-generic' ) );
		}

		return $response;
	}

	/**
	 * Extract and decode the token body of a token response
	 *
	 * @param array<mixed>|WP_Error $token_result The token response.
	 *
	 * @return array<mixed>|WP_Error|null
	 */
	public function get_token_response( $token_result ) {
		if ( ! isset( $token_result['body'] ) ) {
			return new WP_Error( 'missing-token-body', __( 'Missing token body.', 'daggerhart-openid-connect-generic' ), $token_result );
		}

		// Extract the token response from token.
		$token_response = json_decode( $token_result['body'], true );

		// Check that the token response body was able to be parsed.
		if ( is_null( $token_response ) ) {
			return new WP_Error( 'invalid-token', __( 'Invalid token.', 'daggerhart-openid-connect-generic' ), $token_result );
		}

		if ( isset( $token_response['error'] ) ) {
			$error = $token_response['error'];
			$error_description = $error;
			if ( isset( $token_response['error_description'] ) ) {
				$error_description = $token_response['error_description'];
			}
			return new WP_Error( $error, $error_description, $token_result );
		}

		return $token_response;
	}

	/**
	 * Exchange an access_token for a user_claim from the userinfo endpoint
	 *
	 * @param string $access_token The access token supplied from authentication user claim.
	 *
	 * @return array|WP_Error
	 */
	public function request_userinfo( $access_token ) {
		// Allow modifications to the request.
		$request = apply_filters( 'openid-connect-generic-alter-request', array(), 'get-userinfo' );

		/*
		 * Section 5.3.1 of the spec recommends sending the access token using the authorization header
		 * a filter may or may not have already added headers - make sure they exist then add the token.
		 */
		if ( ! array_key_exists( 'headers', $request ) || ! is_array( $request['headers'] ) ) {
			$request['headers'] = array();
		}

		$request['headers']['Authorization'] = 'Bearer ' . $access_token;

		// Add Host header - required for when the openid-connect endpoint is behind a reverse-proxy.
		$parsed_url = parse_url( $this->endpoint_userinfo );
		$host = $parsed_url['host'];

		if ( ! empty( $parsed_url['port'] ) ) {
			$host .= ":{$parsed_url['port']}";
		}

		$request['headers']['Host'] = $host;

		// Attempt the request including the access token in the query string for backwards compatibility.
		$start_time = microtime( true );
		$response   = $this->http_get( $this->endpoint_userinfo, $request );

		// This endpoint can support GET or POST requests according to spec, but some IDPs only allow one.
		// If the GET request failed to produce valid json, attempt a POST request.
		// Spec: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest.
		if ( ! is_wp_error( $response ) && json_decode( $response['body'] ) === null ) {
			$response = $this->http_post( $this->endpoint_userinfo, $request );
		}

		$end_time = microtime( true );
		$this->logger->log( $this->endpoint_userinfo, 'request_userinfo', $end_time - $start_time );

		if ( is_wp_error( $response ) ) {
			$response->add( 'request_userinfo', __( 'Request for userinfo failed.', 'daggerhart-openid-connect-generic' ) );
		}

		return $response;
	}

	/**
	 * Generate a new state, save it as a transient, and return the state hash.
	 *
	 * @param string $redirect_to   The redirect URL to be used after IDP authentication.
	 * @param string $state_binding A value known only to the user agent that starts
	 *                              this flow. When provided, the authorization
	 *                              response is only accepted from that same user
	 *                              agent. An empty value leaves the state unbound.
	 *
	 * @return string
	 */
	public function new_state( $redirect_to, $state_binding = '' ) {
		// New state with cryptographically secure random bytes.
		$state = bin2hex( random_bytes( 16 ) );

		$state_data = array(
			'redirect_to' => $redirect_to,
			// Binds the returned ID token to this request. OIDC Core section 3.1.2.1.
			'nonce'       => bin2hex( random_bytes( 16 ) ),
		);

		/*
		 * Bind the state to the user agent that starts the flow so that an
		 * authorization response cannot be replayed into a different browser.
		 * Only the hash is stored, so a read of the options table does not
		 * disclose a usable binding value.
		 */
		if ( ! empty( $state_binding ) ) {
			$state_data['binding'] = $this->hash_state_binding( $state_binding );
		}

		// Protect the authorization code against interception. RFC 7636.
		if ( $this->enable_pkce ) {
			$state_data['code_verifier'] = $this->new_code_verifier();
		}

		$state_value = array(
			$state => $state_data,
		);

		// Allow storing more data with the state. Eg. to identify user relationships.
		$state_value = apply_filters( 'openid-connect-generic-new-state-value', $state_value, $this );

		set_transient( 'openid-connect-generic-state--' . $state, $state_value, $this->state_time_limit );

		$this->current_state = isset( $state_value[ $state ] ) && is_array( $state_value[ $state ] ) ? $state_value[ $state ] : $state_data;

		return $state;
	}

	/**
	 * Check the existence of a given state transient, verify that it belongs to
	 * the user agent completing the flow, and consume it.
	 *
	 * The state is single use. It is deleted as soon as it has been found, so
	 * that an authorization response cannot be replayed while the state is
	 * still within its time limit.
	 *
	 * @param string $state         The state hash to validate.
	 * @param string $state_binding The user agent's state binding value, when available.
	 *
	 * @return bool
	 */
	public function check_state( $state, $state_binding = '' ) {

		$state_found = true;

		if ( ! get_option( '_transient_openid-connect-generic-state--' . $state ) ) {
			do_action( 'openid-connect-generic-state-not-found', $state );
			$state_found = false;
		}

		$valid = get_transient( 'openid-connect-generic-state--' . $state );

		if ( ! $valid && $state_found ) {
			do_action( 'openid-connect-generic-state-expired', $state );
		}

		if ( ! $valid ) {
			return false;
		}

		// Consume the state before it is used for anything else.
		delete_transient( 'openid-connect-generic-state--' . $state );

		$state_data = ( is_array( $valid ) && isset( $valid[ $state ] ) && is_array( $valid[ $state ] ) ) ? $valid[ $state ] : array();

		/*
		 * A state that was issued with a binding is only valid for the user
		 * agent it was issued to. States without a binding stay acceptable, as
		 * the cookie cannot always be set when the authentication URL is built
		 * (for example when the login button is rendered inside page content
		 * that has already started sending output).
		 */
		if ( ! empty( $state_data['binding'] ) ) {
			if ( empty( $state_binding ) || ! hash_equals( $state_data['binding'], $this->hash_state_binding( $state_binding ) ) ) {
				do_action( 'openid-connect-generic-state-binding-mismatch', $state );
				$this->logger->log(
					'The authorization response was returned to a different browser than the one that started the login.',
					'state-binding-mismatch'
				);
				return false;
			}
		}

		$this->current_state = $state_data;

		return true;
	}

	/**
	 * Hash a state binding value for storage and comparison.
	 *
	 * @param string $state_binding The raw binding value from the user agent.
	 *
	 * @return string
	 */
	private function hash_state_binding( $state_binding ) {
		return hash_hmac( 'sha256', $state_binding, wp_salt( 'nonce' ) );
	}

	/**
	 * Generate a PKCE code verifier.
	 *
	 * @return string A 43 character base64url encoded string. RFC 7636 section 4.1.
	 */
	private function new_code_verifier() {
		return rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Provide the PKCE code challenge for the current authentication flow.
	 *
	 * @return string The S256 code challenge, or an empty string when PKCE is
	 *                not in use for this flow.
	 */
	public function get_state_code_challenge() {
		if ( empty( $this->current_state['code_verifier'] ) ) {
			return '';
		}

		// RFC 7636 section 4.2.
		return rtrim( strtr( base64_encode( hash( 'sha256', $this->current_state['code_verifier'], true ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Provide the nonce of the current authentication flow.
	 *
	 * @return string
	 */
	public function get_state_nonce() {
		return ! empty( $this->current_state['nonce'] ) ? strval( $this->current_state['nonce'] ) : '';
	}

	/**
	 * Provide the redirect URL that was stored with the current state.
	 *
	 * @return string
	 */
	public function get_state_redirect_to() {
		return ! empty( $this->current_state['redirect_to'] ) ? strval( $this->current_state['redirect_to'] ) : '';
	}

	/**
	 * Provide all data stored with the current state.
	 *
	 * @return array<mixed>
	 */
	public function get_state_value() {
		return $this->current_state;
	}

	/**
	 * Get the authorization state from the request
	 *
	 * @param array<string>|WP_Error $request The authentication request results.
	 *
	 * @return string|WP_Error
	 */
	public function get_authentication_state( $request ) {
		if ( ! isset( $request['state'] ) ) {
			return new WP_Error( 'missing-authentication-state', __( 'Missing authentication state.', 'daggerhart-openid-connect-generic' ), $request );
		}

		return $request['state'];
	}

	/**
	 * Ensure that the token meets basic requirements.
	 *
	 * @param array $token_response The token response.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_token_response( $token_response ) {
		/*
		 * Ensure 2 specific items exist with the token response in order
		 * to proceed with confidence:  id_token and token_type == 'Bearer'
		 */
		if ( ! isset( $token_response['id_token'] ) ||
			 ! isset( $token_response['token_type'] ) || strcasecmp( $token_response['token_type'], 'Bearer' )
		) {
			return new WP_Error( 'invalid-token-response', 'Invalid token response', $token_response );
		}

		return true;
	}

	/**
	 * Extract and validate the id_token_claim from the token_response.
	 *
	 * @param array $token_response The token response.
	 *
	 * @return array|WP_Error
	 */
	public function get_id_token_claim( $token_response ) {
		// Validate there is an id_token.
		if ( ! isset( $token_response['id_token'] ) ) {
			return new WP_Error( 'no-identity-token', __( 'No identity token.', 'daggerhart-openid-connect-generic' ), $token_response );
		}

		// Check if JWKS endpoint is configured for JWT signature verification.
		if ( ! empty( $this->endpoint_jwks ) ) {
			// Use configured issuer if provided, otherwise derive from endpoint_login.
			$issuer = ! empty( $this->issuer )
				? $this->issuer
				: $this->get_issuer_from_endpoint( $this->endpoint_login );

			// Use JWT validator for secure signature verification.
			$jwt_validator = new OpenID_Connect_Generic_JWT_Validator(
				$this->endpoint_jwks,
				$this->client_id,
				$issuer,
				$this->jwks_cache_ttl,
				$this->allow_internal_idp,
				$this->logger
			);

			// Validate JWT signature and claims.
			$id_token_claim = $jwt_validator->validate_id_token( $token_response['id_token'] );

			if ( is_wp_error( $id_token_claim ) ) {
				$this->logger->log( $id_token_claim, 'jwt-validation-failed' );
				return $id_token_claim;
			}

			return $id_token_claim;
		}

		$this->logger->log(
			'SECURITY WARNING: JWKS endpoint not configured. JWT signatures are NOT being verified. This is a critical security vulnerability. Configure the JWKS endpoint immediately in Settings > OpenID Connect Client to secure authentication.',
			'jwks-not-configured-insecure'
		);

		// Legacy JWT decoding without signature verification (INSECURE).
		$tmp = explode( '.', $token_response['id_token'] );

		if ( ! isset( $tmp[1] ) ) {
			return new WP_Error( 'missing-identity-token', __( 'Missing identity token.', 'daggerhart-openid-connect-generic' ), $token_response );
		}

		// Extract the id_token's claims from the token (no signature verification).
		$id_token_claim = json_decode(
			base64_decode(
				str_replace( // Because token is encoded in base64 URL (and not just base64).
					array( '-', '_' ),
					array( '+', '/' ),
					$tmp[1]
				)
			),
			true
		);

		return $id_token_claim;
	}

	/**
	 * Extract issuer URL from endpoint URL.
	 *
	 * The issuer is typically the base URL (scheme + host + trailing slash).
	 *
	 * @param string $endpoint_url The full endpoint URL.
	 *
	 * @return string The issuer URL.
	 */
	public function get_issuer_from_endpoint( $endpoint_url ) {
		$parsed = wp_parse_url( $endpoint_url );

		if ( ! $parsed || ! isset( $parsed['scheme'] ) || ! isset( $parsed['host'] ) ) {
			return $endpoint_url;
		}

		$issuer = $parsed['scheme'] . '://' . $parsed['host'];

		// Add port if non-standard.
		if ( isset( $parsed['port'] ) ) {
			$default_ports = array(
				'http' => 80,
				'https' => 443,
			);
			if ( ! isset( $default_ports[ $parsed['scheme'] ] ) || $parsed['port'] != $default_ports[ $parsed['scheme'] ] ) {
				$issuer .= ':' . $parsed['port'];
			}
		}

		return $issuer;
	}

	/**
	 * Ensure the id_token_claim contains the required values.
	 *
	 * @param array       $id_token_claim The ID token claim.
	 * @param string|null $expected_nonce The nonce that was sent with the authentication
	 *                                    request. When empty, no nonce check is performed,
	 *                                    which is the case for tokens obtained through a
	 *                                    refresh instead of an authentication request.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_id_token_claim( $id_token_claim, $expected_nonce = null ) {
		if ( ! is_array( $id_token_claim ) ) {
			return new WP_Error( 'bad-id-token-claim', __( 'Bad ID token claim.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}

		// Validate the identification data and its value.
		if ( ! isset( $id_token_claim['sub'] ) || empty( $id_token_claim['sub'] ) ) {
			return new WP_Error( 'no-subject-identity', __( 'No subject identity.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}

		// Validate expiration claim.
		if ( ! isset( $id_token_claim['exp'] ) ) {
			return new WP_Error( 'missing-exp', __( 'Token missing expiration claim.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}
		if ( time() >= $id_token_claim['exp'] ) {
			return new WP_Error( 'token-expired', __( 'Token has expired.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}

		// Validate issued at claim.
		if ( ! isset( $id_token_claim['iat'] ) ) {
			return new WP_Error( 'missing-iat', __( 'Token missing issued at claim.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}

		// Validate audience claim matches client_id (can be string or array).
		if ( ! isset( $id_token_claim['aud'] ) ) {
			return new WP_Error( 'missing-aud', __( 'Token missing audience claim.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}

		$aud = $id_token_claim['aud'];
		$audience_valid = false;

		if ( is_array( $aud ) ) {
			$audience_valid = in_array( $this->client_id, $aud, true );
		} elseif ( is_string( $aud ) ) {
			$audience_valid = ( $aud === $this->client_id );
		}

		if ( ! $audience_valid ) {
			return new WP_Error( 'invalid-aud', __( 'Token audience does not match client.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
		}

		// Validate issuer claim if configured or endpoint_login is available.
		$expected_issuer = ! empty( $this->issuer ) ?
			$this->issuer :
			( ! empty( $this->endpoint_login ) ? $this->get_issuer_from_endpoint( $this->endpoint_login ) : '' );

		if ( ! empty( $expected_issuer ) ) {
			if ( ! isset( $id_token_claim['iss'] ) ) {
				return new WP_Error( 'missing-iss', __( 'Token missing issuer claim.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
			}

			if ( rtrim( $id_token_claim['iss'], '/' ) !== rtrim( $expected_issuer, '/' ) ) {
				$this->logger->log(
					sprintf(
						'Issuer mismatch - Expected: "%s", Received: "%s". Configure the correct issuer in Settings > OpenID Connect Client > Issuer field, or via the OIDC_ISSUER constant.',
						$expected_issuer,
						$id_token_claim['iss']
					),
					'issuer-mismatch'
				);
				return new WP_Error(
					'invalid-iss',
					__( 'Token issuer does not match expected issuer.', 'daggerhart-openid-connect-generic' ),
					$id_token_claim
				);
			}
		}

		/*
		 * Verify the token was issued for the authentication request that this
		 * flow started, and not replayed from another one.
		 * OIDC Core section 3.1.3.7 item 11.
		 */
		if ( ! empty( $expected_nonce ) ) {
			if ( ! isset( $id_token_claim['nonce'] ) ) {
				return new WP_Error( 'missing-nonce', __( 'Token missing nonce claim.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
			}

			if ( ! hash_equals( strval( $expected_nonce ), strval( $id_token_claim['nonce'] ) ) ) {
				return new WP_Error( 'invalid-nonce', __( 'Token nonce does not match the authentication request.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
			}
		}

		/*
		 * Validate acr values when the option is set in the configuration. A
		 * missing claim is a failure: an IDP that does not confirm the
		 * requested authentication context has not met the requirement.
		 */
		if ( ! empty( $this->acr_values ) ) {
			if ( ! isset( $id_token_claim['acr'] ) ) {
				return new WP_Error( 'missing-acr', __( 'Token missing acr claim.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
			}

			// acr_values is a space separated list of accepted values. OIDC Core section 3.1.2.1.
			$accepted_acr_values = preg_split( '/\s+/', trim( $this->acr_values ) );

			if ( ! in_array( strval( $id_token_claim['acr'] ), $accepted_acr_values, true ) ) {
				return new WP_Error( 'no-match-acr', __( 'No matching acr values.', 'daggerhart-openid-connect-generic' ), $id_token_claim );
			}
		}

		return true;
	}

	/**
	 * Attempt to exchange the access_token for a user_claim.
	 *
	 * @param array $token_response The token response.
	 *
	 * @return array|WP_Error|null
	 */
	public function get_user_claim( $token_response ) {
		// Send a userinfo request to get user claim.
		$user_claim_result = $this->request_userinfo( $token_response['access_token'] );

		// Make sure we didn't get an error, and that the response body exists.
		if ( is_wp_error( $user_claim_result ) || ! isset( $user_claim_result['body'] ) ) {
			return new WP_Error( 'bad-claim', __( 'Bad user claim.', 'daggerhart-openid-connect-generic' ), $user_claim_result );
		}

		$user_claim = json_decode( $user_claim_result['body'], true );

		return $user_claim;
	}

	/**
	 * Make sure the user_claim has all required values, and that the subject
	 * identity matches of the id_token matches that of the user_claim.
	 *
	 * @param array $user_claim     The authenticated user claim.
	 * @param array $id_token_claim The ID token claim.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_user_claim( $user_claim, $id_token_claim ) {
		// Validate the user claim.
		if ( ! is_array( $user_claim ) ) {
			return new WP_Error( 'invalid-user-claim', __( 'Invalid user claim.', 'daggerhart-openid-connect-generic' ), $user_claim );
		}

		// Allow for errors from the IDP.
		if ( isset( $user_claim['error'] ) ) {
			$message = __( 'Error from the IDP.', 'daggerhart-openid-connect-generic' );
			if ( ! empty( $user_claim['error_description'] ) ) {
				$message = $user_claim['error_description'];
			}
			return new WP_Error( 'invalid-user-claim-' . $user_claim['error'], $message, $user_claim );
		}

		// Make sure the id_token sub equals the user_claim sub, according to spec.
		if ( $id_token_claim['sub'] !== $user_claim['sub'] ) {
			return new WP_Error( 'incorrect-user-claim', __( 'Incorrect user claim.', 'daggerhart-openid-connect-generic' ), func_get_args() );
		}

		// Allow for other plugins to alter the login success.
		$login_user = apply_filters( 'openid-connect-generic-user-login-test', true, $user_claim );

		if ( ! $login_user ) {
			return new WP_Error( 'unauthorized', __( 'Unauthorized access.', 'daggerhart-openid-connect-generic' ), $login_user );
		}

		return true;
	}

	/**
	 * Retrieve the subject identity from the id_token.
	 *
	 * @param array $id_token_claim The ID token claim.
	 *
	 * @return mixed
	 */
	public function get_subject_identity( $id_token_claim ) {
		return $id_token_claim['sub'];
	}
}
