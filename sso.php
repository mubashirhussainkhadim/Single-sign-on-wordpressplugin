
<?php
/**
 * Plugin Name: SSO Integration
 * Plugin URI: https://github.com/mubashirhussainkhadim/Single-sign-on-wordpressplugin/edit/main/sso.php
 * Description: Integrates WordPress with SSO.ID for single sign-on capabilities.
 * Version: 1.0
 * Author: Mubashir Hussain
 */

// Options page settings
define('SSO_ID_OPTIONS_KEY', 'sso_id_options');

// Register the admin menu for the plugin settings page.
function sso_id_add_admin_menu() {
    add_menu_page('SSO.ID Integration', 'SSO.ID Settings', 'manage_options', 'sso-id-integration', 'sso_id_settings_page', 'dashicons-admin-generic');
}
add_action('admin_menu', 'sso_id_add_admin_menu');

// The settings page in the admin area.
function sso_id_settings_page() {
    $options = get_option(SSO_ID_OPTIONS_KEY);
    ?>
    <div class="wrap">
        <h2>SSO.ID Integration Settings</h2>
        <form method="post" action="options.php">
            <?php
            settings_fields(SSO_ID_OPTIONS_KEY);
            do_settings_sections('sso-id-integration');
            submit_button();
            ?>
        </form>
        <p>To authenticate via SSO.ID, click the login button below.</p>
        <form action="<?php echo esc_url(admin_url('admin-post.php')); ?>" method="post">
            <?php wp_nonce_field('sso_id_login_nonce', 'sso_id_login_nonce_field'); ?>
            <input type="hidden" name="action" value="sso_id_login">
            <input type="submit" value="Log in with SSO.ID" class="button button-primary">
        </form>
    </div>
    <?php
}

// Initialize the plugin settings
function sso_id_initialize_settings() {
    register_setting(SSO_ID_OPTIONS_KEY, SSO_ID_OPTIONS_KEY, 'sso_id_options_sanitize');
    add_settings_section('sso_id_main', 'API Settings', null, 'sso-id-integration');
    add_settings_field('client_id', 'Client ID', 'sso_id_client_id_render', 'sso-id-integration', 'sso_id_main');
    add_settings_field('client_secret', 'Client Secret', 'sso_id_client_secret_render', 'sso-id-integration', 'sso_id_main');
    add_settings_field('redirect_uri', 'Redirect URI', 'sso_id_redirect_uri_render', 'sso-id-integration', 'sso_id_main');
    add_settings_field('authorize_url', 'Authorize URL', 'sso_id_authorize_url_render', 'sso-id-integration', 'sso_id_main');
    add_settings_field('token_url', 'Token URL', 'sso_id_token_url_render', 'sso-id-integration', 'sso_id_main');
}
add_action('admin_init', 'sso_id_initialize_settings');

// Render the settings fields
function sso_id_client_id_render() {
    $options = get_option(SSO_ID_OPTIONS_KEY);
    echo "<input type='text' name='" . SSO_ID_OPTIONS_KEY . "[client_id]' value='" . esc_attr($options['client_id'] ?? '') . "' />";
}

function sso_id_client_secret_render() {
    $options = get_option(SSO_ID_OPTIONS_KEY);
    echo "<input type='text' name='" . SSO_ID_OPTIONS_KEY . "[client_secret]' value='" . esc_attr($options['client_secret'] ?? '') . "' />";
}

function sso_id_redirect_uri_render() {
    $options = get_option(SSO_ID_OPTIONS_KEY);
    echo "<input type='text' name='" . SSO_ID_OPTIONS_KEY . "[redirect_uri]' value='" . esc_attr($options['redirect_uri'] ?? '') . "' />";
}

function sso_id_authorize_url_render() {
    $options = get_option(SSO_ID_OPTIONS_KEY);
    echo "<input type='text' name='" . SSO_ID_OPTIONS_KEY . "[authorize_url]' value='" . esc_attr($options['authorize_url'] ?? '') . "' />";
}

function sso_id_token_url_render() {
    $options = get_option(SSO_ID_OPTIONS_KEY);
    echo "<input type='text' name='" . SSO_ID_OPTIONS_KEY . "[token_url]' value='" . esc_attr($options['token_url'] ?? '') . "' />";
}

// Sanitize the settings
function sso_id_options_sanitize($input) {
    return array_map('sanitize_text_field', $input);
}

// Redirect the user to the SSO.ID login page.
function sso_id_redirect_to_login() {
    if (!isset($_POST['sso_id_login_nonce_field']) || !wp_verify_nonce($_POST['sso_id_login_nonce_field'], 'sso_id_login_nonce')) {
        wp_die('Invalid nonce');
    }

    $options = get_option(SSO_ID_OPTIONS_KEY);
    $state = wp_create_nonce('sso_id_state');
    $auth_url = esc_url_raw($options['authorize_url']) . "?response_type=code&client_id=" . esc_attr($options['client_id']) . "&redirect_uri=" . urlencode($options['redirect_uri']) . "&state=" . $state;
    wp_redirect($auth_url);
    exit;
}

// Register the custom action hooks for admin-post.php
add_action('admin_post_sso_id_login', 'sso_id_redirect_to_login');

// Handle the OAuth 2.0 callback from SSO.ID.
function sso_id_handle_callback() {
    session_start();
    $state = $_GET['state'] ?? '';
    if (!isset($_GET['code']) || empty($state) || $_SESSION['oauth_state'] !== $state) {
        wp_die('Invalid state or missing authorization code');
    }

    $code = sanitize_text_field($_GET['code']);
    error_log('Received authorization code: ' . $code); // Debugging
    $options = get_option(SSO_ID_OPTIONS_KEY);

    // Exchange authorization code for access token
    $token_data = sso_id_exchange_code_for_token($code, $options);
    error_log('Token data: ' . print_r($token_data, true)); // Debugging
    
    // Login or create user based on token data
    if ($token_data && isset($token_data->access_token)) {
        sso_id_login_user($token_data->access_token, $options);
    } else {
        wp_die('Failed to obtain access token from SSO.ID');
    }
}
add_action('wp_ajax_nopriv_sso_id_callback', 'sso_id_handle_callback');
add_action('wp_ajax_sso_id_callback', 'sso_id_handle_callback');

// Exchange the authorization code for an access token.
function sso_id_exchange_code_for_token($code, $options) {
    error_log('Exchanging authorization code for access token...');

    $response = wp_remote_post($options['token_url'], array(
        'body' => array(
            'grant_type' => 'authorization_code',
            'client_id' => $options['client_id'],
            'client_secret' => $options['client_secret'],
            'redirect_uri' => $options['redirect_uri'],
            'code' => $code
        )
    ));

    error_log('Received response from token endpoint: ' . print_r($response, true)); // Debugging

    if (is_wp_error($response)) {
        wp_die('Error in requesting the access token: ' . $response->get_error_message());
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body);

    error_log('Received data from token endpoint: ' . print_r($data, true)); // Debugging

    if (isset($data->error)) {
        wp_die('Error in exchanging authorization code for access token: ' . $data->error);
    }

    return $data;
}

// Login or create a new user based on the SSO.ID user information.
function sso_id_login_user($access_token, $options) {
    // Fetch user information from SSO.ID using the access token
    $user_info = sso_id_get_user_info($access_token);

    if (!$user_info || !isset($user_info->email)) {
        wp_die('Failed to get user information from SSO.ID.');
    }

    // Check if the user already exists in WordPress
    $user = get_user_by('email', $user_info->email);

    if (!$user) {
        // If the user does not exist, create a new one
        $user_id = wp_create_user($user_info->email, wp_generate_password(), $user_info->email);
        if (is_wp_error($user_id)) {
            wp_die('Error in creating user: ' . $user_id->get_error_message());
        }
        $user = new WP_User($user_id);
        $user->set_role('subscriber');
    }

    // Log the user in
    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID);

    // Redirect to the appropriate page
    wp_redirect(home_url('/'));
    exit;
}

// Fetch user information from SSO.ID using the access token.
function sso_id_get_user_info($access_token) {
    $response = wp_remote_get('https://yoururl.com/oauth/token', array(
        'headers' => array(
            'Authorization' => 'Bearer ' . $access_token
        )
    ));

    if (is_wp_error($response)) {
        return false;
    }

    $body = wp_remote_retrieve_body($response);
    $user_info = json_decode($body);

    if (!$user_info || isset($user_info->error)) {
        return false;
    }

    return $user_info;
}
