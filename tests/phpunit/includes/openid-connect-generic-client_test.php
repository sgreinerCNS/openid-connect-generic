<?php
/**
 * Class OpenID_Connect_Generic_Client_Test
 *
 * @package   OpenID_Connect_Generic
 */

/**
 * Plugin OIDC/oAuth client class test case.
 */
class OpenID_Connect_Generic_Client_Test extends WP_UnitTestCase {

	/**
	 * Test case setup method.
	 *
	 * @return void
	 */
	public function setUp(): void {

		parent::setUp();

	}

	/**
	 * Test case cleanup method.
	 *
	 * @return void
	 */
	public function tearDown(): void {

		parent::tearDown();

	}

	/**
	 * Test plugin get_redirect_uri() method.
	 *
	 * @group ClientTests
	 */
	public function test_plugin_client_get_redirect_uri() {

		$this->assertTrue( true, 'Needs Unit Tests.' );

	}

	/**
	 * Test get_issuer_from_endpoint extracts base URL correctly.
	 *
	 * @dataProvider issuer_extraction_provider
	 * @group ClientTests
	 * @group IssuerValidation
	 *
	 * @param string $endpoint_url    The endpoint URL to test.
	 * @param string $expected_issuer The expected extracted issuer.
	 */
	public function test_get_issuer_from_endpoint( $endpoint_url, $expected_issuer ) {
		$client = $this->create_client();
		$actual = $client->get_issuer_from_endpoint( $endpoint_url );
		$this->assertEquals( $expected_issuer, $actual );
	}

	/**
	 * Data provider for issuer extraction tests.
	 *
	 * @return array Test cases with endpoint URLs and expected issuers.
	 */
	public function issuer_extraction_provider() {
		return array(
			'auth0_authorize'         => array(
				'https://dev-test.us.auth0.com/authorize',
				'https://dev-test.us.auth0.com',
			),
			'keycloak_with_path'      => array(
				'https://auth.example.com/realms/myrealm/protocol/openid-connect/auth',
				'https://auth.example.com',
			),
			'okta_with_path'          => array(
				'https://dev-123456.okta.com/oauth2/default/v1/authorize',
				'https://dev-123456.okta.com',
			),
			'with_non_standard_port'  => array(
				'https://localhost:8443/oauth/authorize',
				'https://localhost:8443',
			),
			'with_standard_https_port' => array(
				'https://example.com:443/authorize',
				'https://example.com',
			),
			'with_standard_http_port' => array(
				'http://example.com:80/authorize',
				'http://example.com',
			),
			'already_base_url'        => array(
				'https://example.com/',
				'https://example.com',
			),
			'no_trailing_slash'       => array(
				'https://example.com',
				'https://example.com',
			),
			'azure_ad'                => array(
				'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
				'https://login.microsoftonline.com',
			),
		);
	}

	/**
	 * Test validate_id_token_claim accepts matching issuer.
	 *
	 * @group ClientTests
	 * @group IssuerValidation
	 */
	public function test_validate_id_token_claim_with_matching_issuer() {
		$client = $this->create_client(
			array(
				'endpoint_login' => 'https://example.com/authorize',
				'client_id'      => 'test_client',
			)
		);

		$id_token_claim = array(
			'sub' => 'user123',
			'iss' => 'https://example.com',  // Matches derived issuer.
			'aud' => 'test_client',
			'exp' => time() + 3600,
			'iat' => time(),
		);

		$result = $client->validate_id_token_claim( $id_token_claim );
		$this->assertTrue( $result );
	}

	/**
	 * Test validate_id_token_claim rejects mismatched issuer.
	 *
	 * @group ClientTests
	 * @group IssuerValidation
	 */
	public function test_validate_id_token_claim_with_wrong_issuer() {
		$client = $this->create_client(
			array(
				'endpoint_login' => 'https://example.com/authorize',
				'client_id'      => 'test_client',
			)
		);

		$id_token_claim = array(
			'sub' => 'user123',
			'iss' => 'https://evil.com',  // Wrong issuer.
			'aud' => 'test_client',
			'exp' => time() + 3600,
			'iat' => time(),
		);

		$result = $client->validate_id_token_claim( $id_token_claim );
		$this->assertWPError( $result );
		$this->assertEquals( 'invalid-iss', $result->get_error_code() );
	}

	/**
	 * Test validate_id_token_claim with Auth0 style issuer.
	 * Note: Auth0 includes trailing slash in issuer, validation should handle both with/without.
	 *
	 * @group ClientTests
	 * @group IssuerValidation
	 */
	public function test_validate_id_token_claim_auth0_format() {
		$client = $this->create_client(
			array(
				'endpoint_login' => 'https://dev-emypzqmunz78not4.us.auth0.com/authorize',
				'client_id'      => 'test_client',
			)
		);

		$id_token_claim = array(
			'sub' => 'auth0|123456',
			'iss' => 'https://dev-emypzqmunz78not4.us.auth0.com/',  // Auth0 includes trailing slash in actual tokens.
			'aud' => 'test_client',
			'exp' => time() + 3600,
			'iat' => time(),
		);

		$result = $client->validate_id_token_claim( $id_token_claim );
		$this->assertTrue( $result );
	}

	/**
	 * Test validate_id_token_claim rejects expired token.
	 *
	 * @group ClientTests
	 * @group IssuerValidation
	 */
	public function test_validate_id_token_claim_rejects_expired() {
		$client = $this->create_client(
			array(
				'endpoint_login' => 'https://example.com/authorize',
				'client_id'      => 'test_client',
			)
		);

		$id_token_claim = array(
			'sub' => 'user123',
			'iss' => 'https://example.com',
			'aud' => 'test_client',
			'exp' => time() - 3600,  // Expired 1 hour ago.
			'iat' => time() - 7200,
		);

		$result = $client->validate_id_token_claim( $id_token_claim );
		$this->assertWPError( $result );
		$this->assertEquals( 'token-expired', $result->get_error_code() );
	}

	/**
	 * Test validate_id_token_claim rejects wrong audience.
	 *
	 * @group ClientTests
	 * @group IssuerValidation
	 */
	public function test_validate_id_token_claim_rejects_wrong_audience() {
		$client = $this->create_client(
			array(
				'endpoint_login' => 'https://example.com/authorize',
				'client_id'      => 'test_client',
			)
		);

		$id_token_claim = array(
			'sub' => 'user123',
			'iss' => 'https://example.com',
			'aud' => 'wrong_client',  // Wrong audience.
			'exp' => time() + 3600,
			'iat' => time(),
		);

		$result = $client->validate_id_token_claim( $id_token_claim );
		$this->assertWPError( $result );
		$this->assertEquals( 'invalid-aud', $result->get_error_code() );
	}

	/**
	 * Test validate_id_token_claim accepts audience as array.
	 *
	 * @group ClientTests
	 * @group IssuerValidation
	 */
	public function test_validate_id_token_claim_with_audience_array() {
		$client = $this->create_client(
			array(
				'endpoint_login' => 'https://example.com/authorize',
				'client_id'      => 'test_client',
			)
		);

		$id_token_claim = array(
			'sub' => 'user123',
			'iss' => 'https://example.com',
			'aud' => array( 'test_client', 'other_client' ),  // Audience as array.
			'exp' => time() + 3600,
			'iat' => time(),
		);

		$result = $client->validate_id_token_claim( $id_token_claim );
		$this->assertTrue( $result );
	}

	/**
	 * Test validate_id_token_claim uses configured issuer over derived issuer.
	 *
	 * @group ClientTests
	 * @group IssuerValidation
	 */
	public function test_validate_id_token_claim_with_explicit_issuer() {
		$client = $this->create_client(
			array(
				'endpoint_login' => 'https://login.example.com/authorize',
				'issuer'         => 'https://issuer.example.com', // Explicit issuer differs from login endpoint.
				'client_id'      => 'test_client',
			)
		);

		$id_token_claim = array(
			'sub' => 'user123',
			'iss' => 'https://issuer.example.com',  // Matches configured issuer, not derived from endpoint_login.
			'aud' => 'test_client',
			'exp' => time() + 3600,
			'iat' => time(),
		);

		$result = $client->validate_id_token_claim( $id_token_claim );
		$this->assertTrue( $result );
	}

	/**
	 * Test that a state can only be redeemed once.
	 *
	 * @group ClientTests
	 * @group StateTests
	 */
	public function test_check_state_consumes_the_state() {
		$client  = $this->create_client();
		$binding = 'aabbccddeeff00112233445566778899';

		$state = $client->new_state( 'https://example.com/page', $binding );

		$this->assertTrue( $client->check_state( $state, $binding ), 'The state should be valid on first use.' );
		$this->assertFalse( $client->check_state( $state, $binding ), 'The state must not be accepted a second time.' );
	}

	/**
	 * Test that a state issued to one user agent is rejected for another.
	 *
	 * @group ClientTests
	 * @group StateTests
	 */
	public function test_check_state_rejects_foreign_binding() {
		$client = $this->create_client();

		$state = $client->new_state( 'https://example.com/page', 'aabbccddeeff00112233445566778899' );

		$this->assertFalse( $client->check_state( $state, '99887766554433221100ffeeddccbbaa' ) );
	}

	/**
	 * Test that a bound state is rejected when the user agent presents no binding.
	 *
	 * @group ClientTests
	 * @group StateTests
	 */
	public function test_check_state_rejects_absent_binding() {
		$client = $this->create_client();

		$state = $client->new_state( 'https://example.com/page', 'aabbccddeeff00112233445566778899' );

		$this->assertFalse( $client->check_state( $state, '' ) );
	}

	/**
	 * Test that a state created without a binding stays usable, which is the
	 * case when the cookie could not be set while building the auth URL.
	 *
	 * @group ClientTests
	 * @group StateTests
	 */
	public function test_check_state_accepts_unbound_state() {
		$client = $this->create_client();

		$state = $client->new_state( 'https://example.com/page' );

		$this->assertTrue( $client->check_state( $state, '' ) );
	}

	/**
	 * Test the redirect target of a state survives the state being consumed.
	 *
	 * @group ClientTests
	 * @group StateTests
	 */
	public function test_state_redirect_to_is_available_after_validation() {
		$client = $this->create_client();

		$state = $client->new_state( 'https://example.com/landing-page' );
		$client->check_state( $state, '' );

		$this->assertEquals( 'https://example.com/landing-page', $client->get_state_redirect_to() );
	}

	/**
	 * Test the PKCE code challenge is the S256 hash of the stored verifier.
	 *
	 * @group ClientTests
	 * @group PkceTests
	 */
	public function test_pkce_code_challenge_is_s256_of_verifier() {
		$client = $this->create_client();
		$client->new_state( 'https://example.com/' );

		$state_value = $client->get_state_value();

		$this->assertNotEmpty( $state_value['code_verifier'], 'A code verifier should be stored with the state.' );
		$this->assertMatchesRegularExpression( '/^[A-Za-z0-9_-]{43}$/', $state_value['code_verifier'], 'The verifier should be a 43 character base64url string.' );

		// RFC 7636 section 4.2.
		$expected = rtrim( strtr( base64_encode( hash( 'sha256', $state_value['code_verifier'], true ) ), '+/', '-_' ), '=' );

		$this->assertEquals( $expected, $client->get_state_code_challenge() );
	}

	/**
	 * Test PKCE can be turned off for identity providers that reject it.
	 *
	 * @group ClientTests
	 * @group PkceTests
	 */
	public function test_pkce_can_be_disabled() {
		$client = $this->create_client( array( 'enable_pkce' => false ) );
		$client->new_state( 'https://example.com/' );

		$state_value = $client->get_state_value();

		$this->assertArrayNotHasKey( 'code_verifier', $state_value );
		$this->assertSame( '', $client->get_state_code_challenge() );
	}

	/**
	 * Test every state carries a nonce for the ID token to be bound to.
	 *
	 * @group ClientTests
	 * @group NonceTests
	 */
	public function test_new_state_creates_a_nonce() {
		$client = $this->create_client();
		$client->new_state( 'https://example.com/' );

		$this->assertNotEmpty( $client->get_state_nonce() );
	}

	/**
	 * Test a token carrying the nonce of a different request is rejected.
	 *
	 * @group ClientTests
	 * @group NonceTests
	 */
	public function test_validate_id_token_claim_rejects_wrong_nonce() {
		$client = $this->create_client();

		$result = $client->validate_id_token_claim( $this->valid_claim( array( 'nonce' => 'some-other-nonce' ) ), 'expected-nonce' );

		$this->assertWPError( $result );
		$this->assertEquals( 'invalid-nonce', $result->get_error_code() );
	}

	/**
	 * Test a token without a nonce is rejected when one was requested.
	 *
	 * @group ClientTests
	 * @group NonceTests
	 */
	public function test_validate_id_token_claim_rejects_missing_nonce() {
		$client = $this->create_client();

		$result = $client->validate_id_token_claim( $this->valid_claim(), 'expected-nonce' );

		$this->assertWPError( $result );
		$this->assertEquals( 'missing-nonce', $result->get_error_code() );
	}

	/**
	 * Test a matching nonce passes validation.
	 *
	 * @group ClientTests
	 * @group NonceTests
	 */
	public function test_validate_id_token_claim_accepts_matching_nonce() {
		$client = $this->create_client();

		$result = $client->validate_id_token_claim( $this->valid_claim( array( 'nonce' => 'expected-nonce' ) ), 'expected-nonce' );

		$this->assertTrue( $result );
	}

	/**
	 * Test the nonce is not checked when none is expected, as is the case for
	 * tokens obtained through a refresh.
	 *
	 * @group ClientTests
	 * @group NonceTests
	 */
	public function test_validate_id_token_claim_skips_nonce_when_none_expected() {
		$client = $this->create_client();

		$this->assertTrue( $client->validate_id_token_claim( $this->valid_claim() ) );
		$this->assertTrue( $client->validate_id_token_claim( $this->valid_claim(), '' ) );
	}

	/**
	 * Test a configured acr value is not silently skipped when the IDP omits
	 * the claim.
	 *
	 * @group ClientTests
	 * @group AcrTests
	 */
	public function test_validate_id_token_claim_requires_acr_when_configured() {
		$client = $this->create_client( array( 'acr_values' => 'urn:mace:incommon:iap:silver' ) );

		$result = $client->validate_id_token_claim( $this->valid_claim() );

		$this->assertWPError( $result );
		$this->assertEquals( 'missing-acr', $result->get_error_code() );
	}

	/**
	 * Test a returned acr value that was not requested is rejected.
	 *
	 * @group ClientTests
	 * @group AcrTests
	 */
	public function test_validate_id_token_claim_rejects_unrequested_acr() {
		$client = $this->create_client( array( 'acr_values' => 'urn:mace:incommon:iap:silver' ) );

		$result = $client->validate_id_token_claim( $this->valid_claim( array( 'acr' => 'urn:mace:incommon:iap:bronze' ) ) );

		$this->assertWPError( $result );
		$this->assertEquals( 'no-match-acr', $result->get_error_code() );
	}

	/**
	 * Test acr_values is treated as the space separated list the spec defines.
	 *
	 * @group ClientTests
	 * @group AcrTests
	 */
	public function test_validate_id_token_claim_accepts_any_requested_acr() {
		$client = $this->create_client( array( 'acr_values' => 'gold silver' ) );

		$this->assertTrue( $client->validate_id_token_claim( $this->valid_claim( array( 'acr' => 'gold' ) ) ) );
		$this->assertTrue( $client->validate_id_token_claim( $this->valid_claim( array( 'acr' => 'silver' ) ) ) );
	}

	/**
	 * Build an otherwise valid ID token claim for the default test client.
	 *
	 * @param array $overrides Claims to add or replace.
	 *
	 * @return array
	 */
	private function valid_claim( $overrides = array() ) {
		return array_merge(
			array(
				'sub' => 'user123',
				'iss' => 'https://example.com',
				'aud' => 'test_client',
				'exp' => time() + 3600,
				'iat' => time(),
			),
			$overrides
		);
	}

	/**
	 * Helper to create client instance for testing.
	 *
	 * @param array $settings Optional settings to override defaults.
	 *
	 * @return OpenID_Connect_Generic_Client
	 */
	private function create_client( $settings = array() ) {
		$default_settings = array(
			'client_id'          => 'test_client',
			'client_secret'      => 'test_secret',
			'scope'              => 'openid email profile',
			'endpoint_login'     => 'https://example.com/authorize',
			'endpoint_userinfo'  => '',
			'endpoint_token'     => 'https://example.com/token',
			'redirect_uri'       => 'https://example.com/callback',
			'acr_values'         => '',
			'endpoint_jwks'      => '',
			'issuer'             => '',
			'jwks_cache_ttl'     => 3600,
			'state_time_limit'   => 180,
			'allow_internal_idp' => false,
			'enable_pkce'        => true,
		);

		$merged = array_merge( $default_settings, $settings );

		$logger = $this->createMock( OpenID_Connect_Generic_Option_Logger::class );

		return new OpenID_Connect_Generic_Client(
			$merged['client_id'],
			$merged['client_secret'],
			$merged['scope'],
			$merged['endpoint_login'],
			$merged['endpoint_userinfo'],
			$merged['endpoint_token'],
			$merged['redirect_uri'],
			$merged['acr_values'],
			$merged['endpoint_jwks'],
			$merged['issuer'],
			$merged['jwks_cache_ttl'],
			$merged['state_time_limit'],
			$merged['allow_internal_idp'],
			$logger,
			$merged['enable_pkce']
		);
	}

}
