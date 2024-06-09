<?php
/**
 * @package kazawallet
 * @version 1.0.0
 */
/*
    Plugin Name: KazaWallet Payment Gateway
    Plugin URI: https://kazawallet.com
    Description: KazaWallet Payment Gateway for WooCommerce
    Requires PHP: 7.4
    Requires at least: 5.6
    Tested up to: 6.4.1
    WC requires at least: 5.6
    WC tested up to: 8.3.1
    Version: 1.0.0
    Author: Kasroad FZE
    Author URI: https://kasroad.com
*/

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

if (!in_array('woocommerce/woocommerce.php', apply_filters('active_plugins', get_option('active_plugins')))) {
    add_action('admin_notices', 'admin_notice');
    return;
}

add_action('plugins_loaded', 'initialize_gateway_class');

add_action('before_woocommerce_init', function () {
    if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
    }
});
function admin_notice()
{
    ?>
    <div class="error">
        <p>KazaWallet is enabled but not effective. It requires WooCommerce to work</p>
    </div>
    <?php
}

function initialize_gateway_class()
{
    add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'plugin_action_links');

    function plugin_action_links($links)
    {
        $settings = array(
            '<a href="' . admin_url('admin.php?page=wc-settings&tab=checkout&section=kazawallet') . '">Settings</a>',
        );
        return array_merge($settings, $links);
    }

    class WC_KazaWallet_Gateway extends WC_Payment_Gateway
    {

        public $domain, $email, $private_key, $publish_key;


        public function __construct()
        {
            $this->domain = hex2bin('68747470733a2f2f6f7574646f6f722e6b6173726f61642e636f6d2f77616c6c65742f6372656174655061796d656e744c696e6b');

            $this->id = 'kazawallet'; // payment gateway ID
            $this->icon = WP_PLUGIN_URL . "/" . plugin_basename(dirname(__FILE__)) . '/assets/logo.png'; // payment gateway icon
            $this->has_fields = false;
            $this->title = __('KazaWallet Gateway', 'text-domain'); // vertical tab title
            $this->method_title = __('KazaWallet Gateway', 'text-domain'); // payment method name
            $this->method_description = __('KazaWallet payment gateway', 'text-domain'); // payment method description

            // load backend options fields
            $this->init_form_fields();

            // load the settings.
            $this->init_settings();

            $this->title = $this->get_option('title');
            $this->description = $this->get_option('description');
            $this->enabled = $this->get_option('enabled');
            $this->email = $this->get_option('email');
            $this->private_key = $this->get_option('private_key');
            $this->publish_key = $this->get_option('publish_key');


            // Action hook to save the settings
            if (is_admin()) {
                add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));
            }


            add_action('woocommerce_api_' . $this->id, array($this, 'webhook'));

        }


        public function init_form_fields()
        {

            $checkout_url = wc_get_checkout_url();
            $checkout_url = trim($checkout_url, '/');

            if (strstr($checkout_url, "?")) {
                $webhookUrl = $checkout_url . "&wc-api=" . $this->id;
            } else {
                $webhookUrl = $checkout_url . "/wc-api/" . $this->id;
            }

            $this->form_fields = array(
                'enabled' => array(
                    'title' => __('Enable/Disable', 'text-domain'),
                    'label' => __('Enable KazaWallet Gateway', 'text-domain'),
                    'type' => 'checkbox',
                    'description' => __('This enable the KazaWallet gateway which allow to accept payment through KazaWallet balance', 'text-domain'),
                    'default' => 'yes',
                    'desc_tip' => true
                ),
                'title' => array(
                    'title' => __('Title', 'text-domain'),
                    'type' => 'text',
                    'description' => __('This controls the title which the user sees during checkout', 'text-domain'),
                    'default' => __('KazaWallet', 'text-domain'),
                ),
                'description' => array(
                    'title' => __('Description', 'text-domain'),
                    'type' => 'textarea',
                    'description' => __('This controls the description which the user sees during checkout.', 'text-domain'),
                    'default' => __('Pay with your balance via our cool KazaWallet payment gateway', 'text-domain'),
                ),
                'email' => array(
                    'title' => __('Merchant Email', 'text-domain'),
                    'type' => 'email',
                    'description' => __('Your login email in KazaWallet gateway', 'text-domain'),

                ),
                'publish_key' => array(
                    'title' => __('API Key', 'text-domain'),
                    'type' => 'text',
                    'description' => __('This value can be obtained from your profile', 'text-domain'),
                ),
                'private_key' => array(
                    'title' => __('API Secret', 'text-domain'),
                    'type' => 'password',
                    'description' => __('Contact customer support to get this value', 'text-domain'),
                ),
                'webhookUrl' => array(
                    'title' => __('Webhook'),
                    'type' => 'text',
                    'description' => __('To get transaction updates, provide our customer support team with this link'),
                    'default' => $webhookUrl,
                    'custom_attributes' => array('readonly' => 'readonly'),
                ),
            );
        }

        public function webhook()
        {
            $payload = file_get_contents("php://input");

            $data = json_decode($payload, true);

            $order_id = wc_get_order_id_by_order_key($data['ref']);
            $order = wc_get_order($order_id);

            $secret = $this->calculate_hash($order->get_total(), $data['id']);

            if ($secret === $data['secret']) {

                if (!$order->is_paid()) {

                    if ($data['status'] === 'fulfilled') {

                        $order->add_order_note("Payment completed via '.$this->title.'API, ID: " . $data['id']);
                        $order->payment_complete();

                        echo json_encode(array(
                            'result' => 'success',
                        ));

                        http_response_code(200);
                        return;

                    } else {

                        $order->add_order_note("Payment timed-out via '.$this->title.'API, ID: " . $data['id']);
                        $order->update_status('failed');

                        return array(
                            'result' => 'success',
                        );
                    }
                } else {
                    wc_add_notice('Order already paid', 'error');
                    return;
                }

            } else {
                wc_add_notice('Please try again.', 'error');
                return;
            }
        }

        private function calculate_hash($amount, $id)
        {
            $secretString = $amount . ":::" . $id . ":::" . $this->publish_key;
            // Generate a SHA-256 hash of the secret string
            $hashDigest = hash('sha256', $secretString, true);
            // Generate an HMAC-SHA512 hash of the SHA-256 hash using the KazaWallet API Secret
            $hmacDigest = hash_hmac('sha512', $hashDigest, $this->private_key, true);
            // Encode the HMAC-SHA512 hash in Base64
            return base64_encode($hmacDigest);
        }

        public function process_payment($order_id)
        {
            global $woocommerce;

            // get order details
            $order = wc_get_order($order_id);

            // Array with arguments for API interaction
            $body = array(
                'amount' => strval($order->get_total()),
                'currency' => $order->get_currency(),
                'email' => $this->email,
                'ref' => $order->get_order_key(),
                'redirectUrl' => $order->get_checkout_order_received_url(),
            );

            $headers = [
                'x-api-key' => $this->publish_key,
                'Content-Type' => 'application/json'
            ];

            $response = wp_remote_post($this->domain,
                array(
                    'headers' => $headers,
                    'body' => json_encode($body)
                )
            );

            if (!is_wp_error($response)) {
                $body = json_decode($response['body'], true);

                if (isset($body['success']) && $body['success'] == true) {

                    $order->update_status('on-hold', __('Awaiting Payment', 'KazaWallet Payment Gateway'));
                    $order->add_order_note("Payment link generated via KazaWallet API, ID: " . $body['id']);

                    // empty cart
                    $woocommerce->cart->empty_cart();

                    // redirect to the thank you page
                    return array(
                        'result' => 'success',
                        'redirect' => $body['url']
                    );

                } else {
                    wc_add_notice('Please try again.', 'error');
                    return;
                }

            } else {
                wc_add_notice('Connection error.', 'error');
                return;
            }

        }

        public function payment_fields()
        {
            if ($this->description) {
                echo wpautop(wp_kses_post($this->description));
            }
        }
    }
}

if (!class_exists('WC_KazaWallet_UpdateChecker')) {

    class WC_KazaWallet_UpdateChecker
    {
        public $plugin_slug, $version, $cache_key, $cache_allowed, $repository;

        public function __construct()
        {
            $this->repository = hex2bin('68747470733a2f2f6b617a6177616c6c65742e636f6d2f776f726470726573732f696e666f2e6a736f6e');
            $this->plugin_slug = 'kazawallet';
            $this->version = '1.0.0';
            $this->cache_key = 'kazawallet';
            $this->cache_allowed = false;

            add_filter('plugins_api', array($this, 'info'), 20, 3);
            add_filter('site_transient_update_plugins', array($this, 'update'));
            add_action('upgrader_process_complete', array($this, 'purge'), 10, 2);
        }

        function info($res, $action, $args)
        {
            // do nothing if you're not getting plugin information right now
            if ('plugin_information' !== $action) {
                return $res;
            }

            // do nothing if it is not our plugin
            if ($this->plugin_slug !== $args->slug) {
                return $res;
            }

            // get updates
            $remote = $this->request();

            if (!$remote) {
                return $res;
            }

            $res = new stdClass();

            $res->name = $remote->name;
            $res->slug = $remote->slug;
            $res->version = $remote->version;
            $res->tested = $remote->tested;
            $res->requires = $remote->requires;
            $res->author = $remote->author;
            $res->author_profile = $remote->author_profile;
            $res->download_link = $remote->download_url;
            $res->trunk = $remote->download_url;
            $res->requires_php = $remote->requires_php;
            $res->last_updated = $remote->last_updated;

            if (isset($remote->rating)) {
                $res->rating = $remote->rating;
            }
            if (isset($remote->num_ratings)) {
                $res->num_ratings = $remote->num_ratings;
            }
            if (isset($remote->downloaded)) {
                $res->downloaded = $remote->downloaded;
            }
            if (isset($remote->active_installs)) {
                $res->active_installs = $remote->active_installs;
            }

            $res->sections = array(
                'description' => $remote->sections->description,
                'installation' => $remote->sections->installation,
                'changelog' => $remote->sections->changelog
            );

            if (!empty($remote->banners)) {
                $res->banners = array(
                    'low' => $remote->banners->low,
                    'high' => $remote->banners->high
                );
            }

            return $res;

        }

        public function request()
        {

            $remote = get_transient($this->cache_key);

            if (false === $remote || !$this->cache_allowed) {

                $remote = wp_remote_get(
                    $this->repository,
                    array(
                        'timeout' => 5,
                        'headers' => array(
                            'Accept' => 'application/json'
                        )
                    )
                );

                if (
                    is_wp_error($remote)
                    || 200 !== wp_remote_retrieve_response_code($remote)
                    || empty(wp_remote_retrieve_body($remote))
                ) {
                    return false;
                }

                set_transient($this->cache_key, $remote, DAY_IN_SECONDS);

            }

            $remote = json_decode(wp_remote_retrieve_body($remote));

            return $remote;

        }

        public function update($transient)
        {

            if (empty($transient->checked)) {
                return $transient;
            }

            $remote = $this->request();

            if (
                $remote
                && version_compare($this->version, $remote->version, '<')
                && version_compare($remote->requires, get_bloginfo('version'), '<=')
                && version_compare($remote->requires_php, PHP_VERSION, '<')
            ) {
                $res = new stdClass();
                $res->slug = $this->plugin_slug;
                $res->plugin = plugin_basename(__FILE__);
                $res->new_version = $remote->version;
                $res->tested = $remote->tested;
                $res->package = $remote->download_url;

                $transient->response[$res->plugin] = $res;

            }

            return $transient;

        }

        public function purge($upgrader, $options)
        {

            if (
                $this->cache_allowed
                && 'update' === $options['action']
                && 'plugin' === $options['type']
            ) {
                // just clean the cache when new plugin version is installed
                delete_transient($this->cache_key);
            }

        }
    }

    new WC_KazaWallet_UpdateChecker();
}

add_filter('woocommerce_payment_gateways', 'add_custom_gateway_class');
function add_custom_gateway_class($gateways)
{
    $gateways[] = 'WC_KazaWallet_Gateway'; // payment gateway class name
    return $gateways;
}