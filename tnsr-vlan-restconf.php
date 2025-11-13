#!/usr/bin/env php
<?php
/**
 * TNSR VLAN Sync - Standalone Test Script
 * 
 * This script allows you to test TNSR VLAN automation independently
 * without needing to go through Tenantos IP assignment process.
 * 
 * Perfect for debugging and development!
 * 
 * Usage:
 *   php test-tnsr-vlan.php create 2602:f937:0:100::/56
 *   php test-tnsr-vlan.php delete 2602:f937:0:100::/56
 *   php test-tnsr-vlan.php verify 2602:f937:0:100::/56
 *   php test-tnsr-vlan.php list
 * 
 * @author Web of Nevada (AS32943)
 * @version 3.3 - Fixed HTTP 412 "too-many-elements" error with PATCH instead of PUT
 */

// ==================== CONFIGURATION ====================

$config = [
    // TNSR Connection
    'tnsr_host'       => '10.10.10.3',
    'tnsr_username'   => 'tenantosapi',
    'tnsr_password'   => 'PWD',
    'tnsr_port'       => 443,
    'use_restconf'    => true,  // true = RESTCONF, false = SSH
    
    // Network Configuration
    'parent_interface' => 'FortyGigabitEthernet65/0/1',
    'ipv6_prefix'      => '2602:f937:0:',
    
    // Script Options
    'dry_run'         => false,  // Set to true to test without making changes
    'verify_ssl'      => false,  // Set to true in production with proper certs
    'verbose'         => true,   // Show detailed output
    //TODO: Add quiet mode to supress all output including whatever can be supressed from the API calls
    //TODO: Potentially add a quiet mode that only shows the programmatically output ERROR, WARNING, SUCCESS messages

];

// ==================== HELPER FUNCTIONS ====================

function log_msg($message, $level = 'INFO') {
    global $config;
    
    $colors = [
        'INFO'    => "\033[0;36m", // Cyan
        'SUCCESS' => "\033[0;32m", // Green
        'WARNING' => "\033[1;33m", // Yellow
        'ERROR'   => "\033[0;31m", // Red
        'DEBUG'   => "\033[0;37m", // Gray
    ];
    
    $reset = "\033[0m";
    $color = $colors[$level] ?? $colors['INFO'];
    
    if ($level === 'DEBUG' && !$config['verbose']) {
        return;
    }
    
    echo "{$color}[{$level}]{$reset} {$message}\n";
}

function extract_vlan_from_subnet($subnet, $prefix) {
    $pattern = '/' . preg_quote($prefix, '/') . '([0-9a-f]+)::/i';
    
    if (!preg_match($pattern, $subnet, $matches)) {
        throw new Exception("Could not extract VLAN ID from subnet: {$subnet}");
    }
    
    $hextet = $matches[1];
    $vlanId = hexdec($hextet);
    
    if ($vlanId < 1 || $vlanId > 4094) {
        throw new Exception("Invalid VLAN ID {$vlanId} (must be 1-4094)");
    }
    
    return $vlanId;
}

function generate_gateway_prefix($subnet, $ipv6_prefix) {
    $pattern = '/' . preg_quote($ipv6_prefix, '/') . '([0-9a-f]+)::/i';
    
    if (!preg_match($pattern, $subnet, $matches)) {
        throw new Exception("Could not extract hextet from subnet: {$subnet}");
    }
    
    $hextet = $matches[1];
    return $ipv6_prefix . 'b' . $hextet;
}

// ==================== RESTCONF FUNCTIONS ====================

function tnsr_restconf_request($method, $path, $data = null) {
    global $config;
    
    $url = "https://{$config['tnsr_host']}:{$config['tnsr_port']}/restconf{$path}";
    
    log_msg("RESTCONF {$method} {$path}", 'DEBUG');
    
    if ($config['dry_run']) {
        log_msg("DRY-RUN: Would {$method} to {$url}", 'WARNING');
        if ($data) {
            log_msg("DRY-RUN: Data:\n" . json_encode($data, JSON_PRETTY_PRINT), 'DEBUG');
        }
        return ['success' => true, 'dry_run' => true];
    }
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    
    if ($data !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }
    
    $headers = ['Accept: application/yang-data+json'];
    if ($method !== 'GET' && $data !== null) {
        $headers[] = 'Content-Type: application/yang-data+json';
    }
    
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_USERPWD, "{$config['tnsr_username']}:{$config['tnsr_password']}");
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $config['verify_ssl']);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $config['verify_ssl'] ? 2 : 0);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception("CURL error: {$error}");
    }
    
    log_msg("Response: HTTP {$httpCode}", 'DEBUG');
    
    // Check for NACM errors even in successful HTTP responses
    if ($httpCode >= 200 && $httpCode < 300 && $response) {
        $data = json_decode($response, true);
        if (isset($data['ietf-restconf:errors']['error'])) {
            $error = $data['ietf-restconf:errors']['error'];
            $errorTag = $error['error-tag'] ?? '';
            $errorMsg = $error['error-message'] ?? '';
            
            if ($errorTag === 'access-denied') {
                throw new Exception("NACM Access Denied: {$errorMsg}. Add user to 'admins' group in NACM or switch to SSH mode.");
            }
            
            throw new Exception("RESTCONF Error: {$errorMsg}");
        }
    }
    
    // 404 is OK for DELETE operations
    if ($httpCode >= 400 && !($method === 'DELETE' && $httpCode == 404)) {
        // Check if it's a NACM error in error response
        if ($response) {
            $data = json_decode($response, true);
            if (isset($data['ietf-restconf:errors']['error']['error-tag'])) {
                $errorTag = $data['ietf-restconf:errors']['error']['error-tag'];
                $errorMsg = $data['ietf-restconf:errors']['error']['error-message'] ?? 'Unknown';
                
                if ($errorTag === 'access-denied') {
                    throw new Exception("NACM Access Denied: {$errorMsg}. Run 'nacm groups group admins; user-name admin' on TNSR or switch to SSH mode");
                }
            }
        }
        
        throw new Exception("TNSR API error: HTTP {$httpCode} - {$response}");
    }
    
    return [
        'success' => true,
        'http_code' => $httpCode,
        'response' => $response ? json_decode($response, true) : null
    ];
}

// ==================== SSH FUNCTIONS ====================

function tnsr_ssh_command($commands) {
    global $config;
    
    if (!is_array($commands)) {
        $commands = [$commands];
    }
    
    log_msg("SSH: Executing " . count($commands) . " commands", 'DEBUG');
    
    if ($config['dry_run']) {
        log_msg("DRY-RUN: Would execute via SSH:", 'WARNING');
        foreach ($commands as $cmd) {
            log_msg("  {$cmd}", 'DEBUG');
        }
        return "DRY-RUN MODE";
    }
    
    if (!function_exists('ssh2_connect')) {
        throw new Exception("PHP SSH2 extension not installed. Run: apt-get install php-ssh2");
    }
    
    $connection = ssh2_connect($config['tnsr_host'], 22);
    if (!$connection) {
        throw new Exception("Failed to connect to TNSR via SSH");
    }
    
    if (!ssh2_auth_password($connection, $config['tnsr_username'], $config['tnsr_password'])) {
        throw new Exception("SSH authentication failed");
    }
    
    $stream = ssh2_shell($connection, 'xterm');
    if (!$stream) {
        throw new Exception("Failed to open SSH shell");
    }
    
    stream_set_blocking($stream, true);
    stream_set_timeout($stream, 30);
    
    // Wait for initial prompt
    usleep(500000);
    fread($stream, 8192);
    
    foreach ($commands as $cmd) {
        fwrite($stream, $cmd . "\n");
        usleep(200000);
    }
    
    fwrite($stream, "exit\n");
    
    $output = '';
    while (!feof($stream)) {
        $line = fgets($stream, 1024);
        if ($line === false) break;
        $output .= $line;
    }
    
    fclose($stream);
    
    return $output;
}

// ==================== INTERFACE FUNCTIONS ====================

function create_subinterface($subnet) {
    global $config;
    
    $vlanId = extract_vlan_from_subnet($subnet, $config['ipv6_prefix']);
    $gatewayPrefix = generate_gateway_prefix($subnet, $config['ipv6_prefix']);
    $gatewayIp = $gatewayPrefix . '::1';
    $customerLinkIp = $gatewayPrefix . '::2';
    
    log_msg("Creating TNSR subinterface", 'INFO');
    log_msg("  Subnet:         {$subnet}", 'INFO');
    log_msg("  VLAN ID:        {$vlanId}", 'INFO');
    log_msg("  Gateway IP:     {$gatewayIp}/64", 'INFO');
    log_msg("  Customer Link:  {$customerLinkIp}", 'INFO');
    echo "\n";
    
    try {
        if ($config['use_restconf']) {
            create_subinterface_restconf($vlanId, $subnet, $gatewayPrefix, $gatewayIp, $customerLinkIp);
        } else {
            create_subinterface_ssh($vlanId, $subnet, $gatewayPrefix, $gatewayIp, $customerLinkIp);
        }
        
        log_msg("✓ Subinterface created successfully", 'SUCCESS');
        echo "\n";
        
        // Verify
        if (verify_subinterface($subnet)) {
            log_msg("✓ Configuration verified successfully", 'SUCCESS');
        } else {
            log_msg("⚠ Configuration may not be correct, verify manually", 'WARNING');
        }
        
    } catch (Exception $e) {
        log_msg("✗ Error creating subinterface: " . $e->getMessage(), 'ERROR');
        throw $e;
    }
}

function create_subinterface_restconf($vlanId, $subnet, $gatewayPrefix, $gatewayIp, $customerLinkIp) {
    global $config;
    
    $interface = $config['parent_interface'];
    $subifName = "{$interface}.{$vlanId}";
    
    log_msg("Creating interface configuration via RESTCONF", 'DEBUG');
    
    // Step 1: Create the subinterface definition
    // NOTE: Use non-namespaced keys that match actual TNSR response format
    log_msg("Step 1: Creating subinterface definition for {$subifName}", 'INFO');
    
    $subifConfig = [
        'netgate-interface:subif-entry' => [
            [
                'subid' => $vlanId,
                'vlan' => [
                    'exact-match' => true,
                    'outer-vlan-id' => $vlanId
                ],
                'if-name' => $interface
            ]
        ]
    ];
    
    tnsr_restconf_request(
        'POST',
        "/data/netgate-interface:interfaces-config/subinterfaces",
        $subifConfig
    );
    
    log_msg("✓ Subinterface definition created for {$subifName}", 'SUCCESS');
    
    // Step 2: Enable the interface and configure IPv6 address
    log_msg("Step 2: Configuring interface {$subifName}", 'INFO');
    
    $interfaceConfig = [
        'netgate-interface:interface' => [
            [
                'name' => $subifName,
                'enabled' => true,
                'ipv6' => [
                    'address' => [
                        'ip' => [
                            "{$gatewayIp}/64"
                        ]
                    ]
                ]
            ]
        ]
    ];
    
    tnsr_restconf_request(
        'PUT',
        '/data/netgate-interface:interfaces-config/interface=' . urlencode($subifName),
        $interfaceConfig
    );
    
    log_msg("✓ Interface {$subifName} configured", 'SUCCESS');
    
    // Step 3: Configure IPv6 Router Advertisements
    log_msg("Step 3: Configuring IPv6 router advertisements", 'INFO');
    
    $raConfig = [
        'netgate-ipv6-ra:ipv6-router-advertisements' => [
            'send-advertisements' => true,
            'default-lifetime' => 1800,
            'prefix-list' => [
                'prefix' => [
                    [
                        'prefix-spec' => $gatewayPrefix . '::/64',
                        'valid-lifetime' => 2592000,
                        'preferred-lifetime' => 604800,
                        'on-link-flag' => true,
                        'autonomous-flag' => true
                    ]
                ]
            ]
        ]
    ];
    
    try {
        tnsr_restconf_request(
            'PUT',
            '/data/netgate-interface:interfaces-config/interface=' . urlencode($subifName) . 
            '/ipv6/netgate-ipv6-ra:ipv6-router-advertisements',
            $raConfig
        );
        log_msg("✓ IPv6 router advertisements configured", 'SUCCESS');
    } catch (Exception $e) {
        log_msg("⚠ Warning configuring router advertisements: " . $e->getMessage(), 'WARNING');
    }
    
    // Step 4: Add static route
    log_msg("Step 4: Adding static route for {$subnet}", 'DEBUG');
    create_route_restconf($subnet, $subifName, $customerLinkIp);
}

function create_route_restconf($subnet, $subifName, $customerLinkIp) {
    global $config;
    
    log_msg("Fetching current route table configuration", 'DEBUG');
    
    // Step 1: GET the current route table
    $getResult = tnsr_restconf_request('GET', '/data/netgate-route-table:route-table-config');
    $routeConfig = $getResult['response'] ?? [];
    
    log_msg("Current route config structure: " . json_encode(array_keys($routeConfig), JSON_PRETTY_PRINT), 'DEBUG');
    
    if (empty($routeConfig)) {
        log_msg("Route table is empty, creating new structure", 'DEBUG');
        // Create with NON-namespaced keys as TNSR expects when sending back
        $routeConfig = [
            'netgate-route-table:route-table-config' => [
                'static-routes' => [
                    'route-table' => [
                        [
                            'name' => 'default',
                            'id' => 0,
                            'ipv6-routes' => [
                                'route' => []
                            ]
                        ]
                    ]
                ]
            ]
        ];
    }
    
    // Step 2: Create the new route object with NON-namespaced keys
    $newRoute = [
        'destination-prefix' => $subnet,
        'next-hop' => [
            'hop' => [
                [
                    'hop-id' => 0,
                    'ipv6-address' => $customerLinkIp,
                    'if-name' => $subifName
                ]
            ]
        ]
    ];
    
    // Step 3: Navigate using non-namespaced keys
    $configKey = 'netgate-route-table:route-table-config';
    $staticRoutesKey = 'static-routes';
    $routeTableKey = 'route-table';
    $ipv6RoutesKey = 'ipv6-routes';
    $routeKey = 'route';
    
    // Ensure structure exists
    if (!isset($routeConfig[$configKey][$staticRoutesKey][$routeTableKey])) {
        log_msg("Creating route table structure", 'DEBUG');
        $routeConfig[$configKey][$staticRoutesKey][$routeTableKey] = [
            [
                'name' => 'default',
                'id' => 0,
                'ipv6-routes' => [
                    'route' => []
                ]
            ]
        ];
    }
    
    // Step 4: Find default table and add route
    $routeExists = false;
    $found = false;
    
    foreach ($routeConfig[$configKey][$staticRoutesKey][$routeTableKey] as &$table) {
        $tableName = $table['name'] ?? 'unknown';
        
        if ($tableName === 'default') {
            log_msg("Found default route table", 'DEBUG');
            
            // Ensure IPv6 routes structure exists
            if (!isset($table[$ipv6RoutesKey])) {
                $table[$ipv6RoutesKey] = ['route' => []];
            }
            if (!isset($table[$ipv6RoutesKey][$routeKey])) {
                $table[$ipv6RoutesKey][$routeKey] = [];
            }
            
            // Check if route already exists
            foreach ($table[$ipv6RoutesKey][$routeKey] as $existingRoute) {
                $existingPrefix = $existingRoute['destination-prefix'] ?? '';
                if ($existingPrefix === $subnet) {
                    $routeExists = true;
                    log_msg("Route for {$subnet} already exists", 'WARNING');
                    break;
                }
            }
            
            if (!$routeExists) {
                log_msg("Adding new route to default table", 'DEBUG');
                $table[$ipv6RoutesKey][$routeKey][] = $newRoute;
                log_msg("Route added, total routes now: " . count($table[$ipv6RoutesKey][$routeKey]), 'DEBUG');
            }
            $found = true;
            break;
        }
    }
    
    if (!$found) {
        log_msg("Default route table not found, creating new one", 'WARNING');
        $routeConfig[$configKey][$staticRoutesKey][$routeTableKey][] = [
            'name' => 'default',
            'id' => 0,
            'ipv6-routes' => [
                'route' => [$newRoute]
            ]
        ];
    }
    
    if ($routeExists) {
        log_msg("Route already exists, not modifying", 'INFO');
        return;
    }
    
    // Step 5: Use PATCH instead of PUT to avoid HTTP 412 "too-many-elements" error
    log_msg("Sending PATCH request to merge route (this avoids HTTP 412 error)", 'DEBUG');
    
    tnsr_restconf_request(
        'PATCH',
        '/data/netgate-route-table:route-table-config',
        $routeConfig
    );
    
    log_msg("✓ Route added via PATCH merge", 'SUCCESS');
}

function delete_subinterface($subnet) {
    global $config;
    
    $vlanId = extract_vlan_from_subnet($subnet, $config['ipv6_prefix']);
    
    log_msg("Deleting TNSR subinterface for VLAN {$vlanId}", 'INFO');
    log_msg("  Subnet:  {$subnet}", 'INFO');
    log_msg("  VLAN ID: {$vlanId}", 'INFO');
    echo "\n";
    
    try {
        if ($config['use_restconf']) {
            delete_subinterface_restconf($vlanId, $subnet);
        } else {
            delete_subinterface_ssh($vlanId, $subnet);
        }
        
        log_msg("✓ Subinterface deleted successfully", 'SUCCESS');
        
    } catch (Exception $e) {
        log_msg("✗ Error deleting subinterface: " . $e->getMessage(), 'ERROR');
        throw $e;
    }
}

function delete_subinterface_restconf($vlanId, $subnet) {
    global $config;
    
    $interface = $config['parent_interface'];
    $subifName = "{$interface}.{$vlanId}";
    
    log_msg("Deleting route for {$subnet}", 'DEBUG');
    
    // Step 1: Delete the route
    delete_route_restconf($subnet);
    
    log_msg("Deleting interface {$subifName}", 'DEBUG');
    
    // Step 2: Delete the interface configuration
    tnsr_restconf_request(
        'DELETE',
        '/data/netgate-interface:interfaces-config/interface=' . urlencode($subifName)
    );
    log_msg("✓ Interface {$subifName} deleted", 'SUCCESS');
    
    // Step 3: Delete the subinterface definition
    log_msg("Deleting subinterface definition for VLAN {$vlanId}", 'DEBUG');
    
    try {
        tnsr_restconf_request(
            'DELETE',
            '/data/netgate-interface:interfaces-config/subinterfaces/subif-entry=' . urlencode($interface) . ',' . $vlanId
        );
        log_msg("✓ Subinterface definition deleted", 'SUCCESS');
    } catch (Exception $e) {
        log_msg("⚠ Warning deleting subinterface definition: " . $e->getMessage(), 'WARNING');
    }
}

function delete_route_restconf($subnet) {
    log_msg("Fetching current route table for deletion", 'DEBUG');
    
    // Get current config
    $getResult = tnsr_restconf_request('GET', '/data/netgate-route-table:route-table-config');
    $routeConfig = $getResult['response'] ?? [];
    
    if (empty($routeConfig)) {
        log_msg("No routes to delete", 'WARNING');
        return;
    }
    
    // Find and remove the route using non-namespaced keys
    $found = false;
    $configKey = 'netgate-route-table:route-table-config';
    $staticRoutesKey = 'static-routes';
    $routeTableKey = 'route-table';
    $ipv6RoutesKey = 'ipv6-routes';
    $routeKey = 'route';
    
    if (isset($routeConfig[$configKey][$staticRoutesKey][$routeTableKey])) {
        foreach ($routeConfig[$configKey][$staticRoutesKey][$routeTableKey] as &$table) {
            $tableName = $table['name'] ?? 'unknown';
            if ($tableName === 'default') {
                if (isset($table[$ipv6RoutesKey][$routeKey])) {
                    foreach ($table[$ipv6RoutesKey][$routeKey] as $key => $route) {
                        $prefix = $route['destination-prefix'] ?? '';
                        if ($prefix === $subnet) {
                            log_msg("Found route {$subnet}, removing", 'DEBUG');
                            unset($table[$ipv6RoutesKey][$routeKey][$key]);
                            $found = true;
                            break;
                        }
                    }
                    
                    // Re-index array
                    $table[$ipv6RoutesKey][$routeKey] = array_values($table[$ipv6RoutesKey][$routeKey]);
                }
                break;
            }
        }
    }
    
    if (!$found) {
        log_msg("Route {$subnet} not found", 'WARNING');
        return;
    }
    
    // Use PUT (not PATCH) to properly delete the route
    // PUT replaces the entire structure, so by excluding the deleted route,
    // it will be removed from TNSR
    log_msg("Sending PUT request to replace route table (excludes deleted route)", 'DEBUG');
    
    tnsr_restconf_request(
        'PUT',
        '/data/netgate-route-table:route-table-config',
        $routeConfig
    );
    
    log_msg("✓ Route deleted via PUT replacement", 'SUCCESS');
}

function delete_subinterface_ssh($vlanId, $subnet) {
    global $config;
    
    $interface = $config['parent_interface'];
    $gatewayPrefix = generate_gateway_prefix($subnet, $config['ipv6_prefix']);
    
    $commands = [
        'configure',
        
        // Delete the interface
        "no interface {$interface}.{$vlanId}",
        
        // Delete the route
        'route table default',
        "no route {$subnet}",
        'exit',
        
        'write memory',
        'exit'
    ];
    
    $output = tnsr_ssh_command($commands);
    
    if ($config['verbose']) {
        log_msg("SSH Output:\n{$output}", 'DEBUG');
    }
}

function create_subinterface_ssh($vlanId, $subnet, $gatewayPrefix, $gatewayIp, $customerLinkIp) {
    global $config;
    
    $interface = $config['parent_interface'];
    
    $commands = [
        'configure',
        
        // Create VLAN subinterface
        "interface subif {$interface} {$vlanId}",
        'exact-match',
        "outer-dot1q {$vlanId}",
        'exit',
        
        // Configure subinterface
        "interface {$interface}.{$vlanId}",
        'enable',
        "ipv6 address {$gatewayIp}/64",
        
        // Configure router advertisements
        'ipv6 router-advertisements',
        'send-advertisements true',
        'default-lifetime 1800',
        "prefix {$gatewayPrefix}::/64",
        'valid-lifetime 2592000',
        'preferred-lifetime 604800',
        'on-link-flag true',
        'autonomous-flag true',
        'exit',
        'exit',
        'exit',
        
        // Add static route
        'route table default',
        "route {$subnet}",
        "next-hop 0 via {$customerLinkIp} {$interface}.{$vlanId}",
        'exit',
        'exit',
        
        'write memory',
        'exit'
    ];
    
    $output = tnsr_ssh_command($commands);
    
    if ($config['verbose']) {
        log_msg("SSH Output:\n{$output}", 'DEBUG');
    }
}

function verify_subinterface($subnet) {
    global $config;
    
    $vlanId = extract_vlan_from_subnet($subnet, $config['ipv6_prefix']);
    $interface = $config['parent_interface'];
    $subifName = "{$interface}.{$vlanId}";
    $gatewayPrefix = generate_gateway_prefix($subnet, $config['ipv6_prefix']);
    $gatewayIp = $gatewayPrefix . '::1';
    
    log_msg("Verifying subinterface configuration", 'INFO');
    echo "\n";
    
    $allPassed = true;
    
    if ($config['use_restconf']) {
        // Verify interface exists
        try {
            $result = tnsr_restconf_request('GET', '/data/netgate-interface:interfaces-config/interface=' . urlencode($subifName));
            if ($result['http_code'] === 200) {
                log_msg("✓ Subinterface {$subifName} exists", 'SUCCESS');
            } else {
                log_msg("✗ Subinterface {$subifName} not found", 'ERROR');
                $allPassed = false;
            }
        } catch (Exception $e) {
            log_msg("✗ Error checking subinterface: " . $e->getMessage(), 'ERROR');
            $allPassed = false;
        }
        
        // Verify IPv6 address
        try {
            $result = tnsr_restconf_request('GET', '/data/netgate-interface:interfaces-config/interface=' . urlencode($subifName));
            if ($result['http_code'] === 200 && isset($result['response']['netgate-interface:interface'][0]['netgate-interface:interface']['netgate-interface:ipv6']['netgate-interface:address'])) {
                $addresses = $result['response']['netgate-interface:interface'][0]['netgate-interface:interface']['netgate-interface:ipv6']['netgate-interface:address'];
                $found = false;
                foreach ($addresses as $addr) {
                    if ($addr['netgate-interface:ip'] === $gatewayIp) {
                        $found = true;
                        break;
                    }
                }
                if ($found) {
                    log_msg("✓ Gateway IP {$gatewayIp}/64 is configured", 'SUCCESS');
                } else {
                    log_msg("✗ Gateway IP {$gatewayIp} not found", 'ERROR');
                    $allPassed = false;
                }
            }
        } catch (Exception $e) {
            log_msg("⚠ Warning checking IPv6 address: " . $e->getMessage(), 'WARNING');
        }
        
        // Verify route exists
        try {
            $result = tnsr_restconf_request('GET', '/data/netgate-route-table:route-table-config');
            if ($result['http_code'] === 200) {
                $found = false;
                // Use non-namespaced keys to match actual TNSR response format
                $routeTableConfig = $result['response']['netgate-route-table:route-table-config'];
                $staticRoutes = $routeTableConfig['static-routes'] ?? [];
                $tableConfig = $staticRoutes['route-table'] ?? [];
                
                foreach ($tableConfig as $table) {
                    $tableName = $table['name'] ?? 'unknown';
                    if ($tableName === 'default') {
                        $ipv6Routes = $table['ipv6-routes'] ?? [];
                        $routes = $ipv6Routes['route'] ?? [];
                        foreach ($routes as $route) {
                            $prefix = $route['destination-prefix'] ?? '';
                            if ($prefix === $subnet) {
                                $found = true;
                                break;
                            }
                        }
                    }
                }
                
                if ($found) {
                    log_msg("✓ Static route for {$subnet} exists", 'SUCCESS');
                } else {
                    log_msg("✗ Static route for {$subnet} not found", 'ERROR');
                    $allPassed = false;
                }
            }
        } catch (Exception $e) {
            log_msg("⚠ Warning checking route: " . $e->getMessage(), 'WARNING');
        }
    } else {
        // SSH verification
        try {
            $output = tnsr_ssh_command("show interface {$subifName}");
            if (strpos($output, $subifName) !== false && strpos($output, 'error') === false) {
                log_msg("✓ Subinterface {$subifName} exists", 'SUCCESS');
            } else {
                log_msg("✗ Subinterface {$subifName} not found", 'ERROR');
                $allPassed = false;
            }
        } catch (Exception $e) {
            log_msg("⚠ Warning checking via SSH: " . $e->getMessage(), 'WARNING');
        }
    }
    
    echo "\n";
    return $allPassed;
}

function list_subinterfaces() {
    global $config;
    
    log_msg("Listing TNSR subinterfaces", 'INFO');
    echo "\n";
    
    if ($config['use_restconf']) {
        try {
            $result = tnsr_restconf_request('GET', '/data/netgate-interface:interfaces-config');
            
            if ($result['http_code'] === 200) {
                // The response can have different key formats depending on TNSR version
                $configData = $result['response']['netgate-interface:interfaces-config'] ?? [];
                
                if (empty($configData)) {
                    log_msg("No interface config found", 'WARNING');
                } else {
                    // Try different key formats for interfaces array
                    // Some versions use 'netgate-interface:interface', others use just 'interface'
                    $interfaces = $configData['netgate-interface:interface'] ?? 
                                  $configData['interface'] ?? [];
                    
                    if (empty($interfaces)) {
                        log_msg("No interfaces found in response", 'DEBUG');
                    }
                    
                    $count = 0;
                    
                    foreach ($interfaces as $interface) {
                        // Try both namespaced and non-namespaced keys
                        $name = $interface['netgate-interface:name'] ?? $interface['name'] ?? 'unknown';
                        
                        if (strpos($name, '.') !== false) {  // Only show subinterfaces
                            // Try both key formats for enabled/description
                            $enabled = $interface['netgate-interface:enabled'] ?? $interface['enabled'] ?? false;
                            $description = $interface['netgate-interface:description'] ?? $interface['description'] ?? '';
                            
                            $status = $enabled ? 'up' : 'down';
                            log_msg("  {$name} ({$status}) - {$description}", 'INFO');
                            
                            // Try to extract IPv6 address from nested structure
                            $ipv6 = $interface['netgate-interface:interface']['netgate-interface:ipv6']['netgate-interface:address'] ?? 
                                    $interface['ipv6']['address']['ip'] ?? [];
                            
                            // Handle both single address and array of addresses
                            if (!empty($ipv6)) {
                                if (isset($ipv6['netgate-interface:ip'])) {
                                    // Single address with namespace
                                    log_msg("    IPv6: {$ipv6['netgate-interface:ip']}", 'DEBUG');
                                } elseif (is_array($ipv6)) {
                                    // Array of addresses (could have or not have namespace)
                                    foreach ($ipv6 as $addr) {
                                        if (is_string($addr)) {
                                            log_msg("    IPv6: {$addr}", 'DEBUG');
                                        } elseif (isset($addr['netgate-interface:ip'])) {
                                            log_msg("    IPv6: {$addr['netgate-interface:ip']}", 'DEBUG');
                                        }
                                    }
                                }
                            }
                            
                            $count++;
                        }
                    }
                    
                    if ($count === 0) {
                        log_msg("No subinterfaces found", 'WARNING');
                    } else {
                        log_msg("Total subinterfaces: {$count}", 'INFO');
                    }
                }
            } else {
                log_msg("No interfaces found (HTTP {$result['http_code']})", 'WARNING');
            }
        } catch (Exception $e) {
            log_msg("Error listing interfaces: " . $e->getMessage(), 'ERROR');
        }
    } else {
        try {
            $output = tnsr_ssh_command("show interface brief");
            log_msg($output, 'INFO');
        } catch (Exception $e) {
            log_msg("Error listing interfaces: " . $e->getMessage(), 'ERROR');
        }
    }
    
    echo "\n";
    
    // Also list routes
    log_msg("Listing routes", 'INFO');
    echo "\n";
    
    if ($config['use_restconf']) {
        try {
            $result = tnsr_restconf_request('GET', '/data/netgate-route-table:route-table-config');
            
            if ($result['http_code'] === 200) {
                // Navigate the nested structure carefully - handle both namespaced and non-namespaced keys
                $routeTableConfig = $result['response']['netgate-route-table:route-table-config'] ?? [];
                
                if (empty($routeTableConfig)) {
                    log_msg("Route table config is empty", 'WARNING');
                } else {
                    // Try different key formats for static routes
                    $staticRoutes = $routeTableConfig['netgate-route-table:static-routes'] ?? 
                                   $routeTableConfig['static-routes'] ?? [];
                    
                    if (empty($staticRoutes)) {
                        log_msg("No static routes found", 'WARNING');
                    } else {
                        // Try different key formats for route tables
                        $tableConfig = $staticRoutes['netgate-route-table:route-table'] ?? 
                                      $staticRoutes['route-table'] ?? [];
                        
                        if (empty($tableConfig)) {
                            log_msg("No route tables found", 'WARNING');
                        } else {
                            foreach ($tableConfig as $table) {
                                // Try both key formats for table name
                                $tableName = $table['netgate-route-table:name'] ?? $table['name'] ?? 'unknown';
                                
                                if ($tableName === 'default') {
                                    // Try different key formats for IPv6 routes
                                    $ipv6Routes = $table['netgate-route-table:ipv6-routes'] ?? 
                                                  $table['ipv6-routes'] ?? [];
                                    
                                    if (empty($ipv6Routes)) {
                                        log_msg("No IPv6 routes configured", 'WARNING');
                                    } else {
                                        // Try different key formats for route array
                                        $routes = $ipv6Routes['netgate-route-table:route'] ?? 
                                                  $ipv6Routes['route'] ?? [];
                                        
                                        if (count($routes) === 0) {
                                            log_msg("No IPv6 routes configured", 'WARNING');
                                        } else {
                                            foreach ($routes as $route) {
                                                // Try both key formats
                                                $prefix = $route['netgate-route-table:destination-prefix'] ?? 
                                                         $route['destination-prefix'] ?? 'unknown';
                                                
                                                $nextHopData = $route['netgate-route-table:next-hop'] ?? 
                                                               $route['next-hop'] ?? [];
                                                
                                                // Get the hop array
                                                $hopArray = $nextHopData['netgate-route-table:hop'] ?? 
                                                            $nextHopData['hop'] ?? [];
                                                
                                                if (!empty($hopArray) && is_array($hopArray)) {
                                                    $hop = $hopArray[0] ?? [];
                                                    $via = $hop['netgate-route-table:ipv6-address'] ?? 
                                                           $hop['ipv6-address'] ?? 'local';
                                                    $interface = $hop['netgate-route-table:if-name'] ?? 
                                                                $hop['if-name'] ?? 'local';
                                                    
                                                    log_msg("  {$prefix} via {$via} {$interface}", 'INFO');
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                log_msg("Failed to get route table (HTTP {$result['http_code']})", 'WARNING');
            }
        } catch (Exception $e) {
            log_msg("Error listing routes: " . $e->getMessage(), 'ERROR');
        }
    } else {
        try {
            $output = tnsr_ssh_command("show route ipv6");
            log_msg($output, 'INFO');
        } catch (Exception $e) {
            log_msg("Error listing routes: " . $e->getMessage(), 'ERROR');
        }
    }
    
    echo "\n";
}

function show_usage() {
    echo "
╔════════════════════════════════════════════════════════╗
║         TNSR VLAN Sync - Standalone Test Script        ║
╚════════════════════════════════════════════════════════╝

Usage:
  php tnsr-vlan-restconf-FIXED.php <command> [options]

Commands:
  create <subnet>       Create a new customer subinterface
                        Example: create 2602:f937:0:100::/56
  
  delete <subnet>       Delete a customer subinterface
                        Example: delete 2602:f937:0:100::/56
  
  verify <subnet>       Verify subinterface configuration
                        Example: verify 2602:f937:0:100::/56
  
  list                  List all subinterfaces and routes
  
  diagnose              Run diagnostic tests
  
  test                  Interactive test mode

Configuration:
  Edit the \$config array at the top of this script to set:
  - TNSR host and credentials
  - Parent interface name
  - IPv6 prefix
  - RESTCONF vs SSH mode

Examples:
  # Create a VLAN subinterface
  php tnsr-vlan-restconf-FIXED.php create 2602:f937:0:100::/56
  
  # List all subinterfaces
  php tnsr-vlan-restconf-FIXED.php list
  
  # Verify configuration
  php tnsr-vlan-restconf-FIXED.php verify 2602:f937:0:100::/56
  
  # Delete a subinterface
  php tnsr-vlan-restconf-FIXED.php delete 2602:f937:0:100::/56

Version: 3.3 (Fixed HTTP 412 error with PATCH instead of PUT)
";
}

function diagnose_connection() {
    global $config;
    
    echo "\n";
    echo "╔════════════════════════════════════════════════════╗\n";
    echo "║      TNSR VLAN Sync - Diagnostic Mode              ║\n";
    echo "╚════════════════════════════════════════════════════╝\n";
    echo "\n";
    
    log_msg("TNSR Connection Diagnostic", 'INFO');
    log_msg(str_repeat('═', 50), 'INFO');
    echo "\n";
    
    // Test 1: Connection test
    log_msg("Test 1: RESTCONF Connection", 'INFO');
    log_msg(str_repeat('─', 50), 'INFO');
    
    try {
        $result = tnsr_restconf_request('GET', '/data/netgate-system:system/host-name');
        
        if ($result['http_code'] === 200) {
            log_msg("✓ Successfully connected to TNSR RESTCONF API", 'SUCCESS');
            
            $hostname = $result['response']['netgate-system:host-name'] ?? 'unknown';
            log_msg("  Hostname: {$hostname}", 'INFO');
        } else {
            log_msg("✗ Unexpected HTTP response: " . $result['http_code'], 'ERROR');
        }
    } catch (Exception $e) {
        log_msg("✗ Connection failed: " . $e->getMessage(), 'ERROR');
    }
    
    echo "\n";
    
    // Test 2: Authentication test
    log_msg("Test 2: Authentication", 'INFO');
    log_msg(str_repeat('─', 50), 'INFO');
    
    try {
        $result = tnsr_restconf_request('GET', '/operations/ietf-netconf:get-config');
        log_msg("✓ Authentication successful", 'SUCCESS');
    } catch (Exception $e) {
        if (strpos($e->getMessage(), 'Access Denied') !== false) {
            log_msg("✗ NACM Access Denied - User may not have permissions", 'ERROR');
            log_msg("  Run on TNSR: nacm groups group admins; user-name tenantosapi", 'WARNING');
        } else {
            log_msg("✗ Authentication error: " . $e->getMessage(), 'ERROR');
        }
    }
    
    echo "\n";
    
    // Test 3: Route table access
    log_msg("Test 3: Route Table Access", 'INFO');
    log_msg(str_repeat('─', 50), 'INFO');
    
    try {
        $result = tnsr_restconf_request('GET', '/data/netgate-route-table:route-table-config');
        
        if ($result['http_code'] === 200) {
            log_msg("✓ Route table is accessible", 'SUCCESS');
            
            $tableConfig = $result['response']['netgate-route-table:route-table-config']['netgate-route-table:static-routes']['netgate-route-table:route-table'] ?? [];
            
            foreach ($tableConfig as $table) {
                $name = $table['netgate-route-table:name'] ?? 'unknown';
                $routes = $table['netgate-route-table:ipv6-routes']['netgate-route-table:route'] ?? [];
                log_msg("  Table '{$name}': " . count($routes) . " routes", 'INFO');
            }
        } else {
            log_msg("✗ Route table not accessible: HTTP " . $result['http_code'], 'ERROR');
        }
    } catch (Exception $e) {
        log_msg("✗ Error accessing route table: " . $e->getMessage(), 'ERROR');
    }
    
    echo "\n";
    
    // Test 4: Interface access
    log_msg("Test 4: Interface Configuration Access", 'INFO');
    log_msg(str_repeat('─', 50), 'INFO');
    
    try {
        $result = tnsr_restconf_request('GET', '/data/netgate-interface:interfaces-config');
        
        if ($result['http_code'] === 200) {
            $interfaces = $result['response']['netgate-interface:interface'] ?? [];
            log_msg("✓ Interface configuration is accessible", 'SUCCESS');
            log_msg("  Total interfaces: " . count($interfaces), 'INFO');
        } else {
            log_msg("✗ Interface config not accessible: HTTP " . $result['http_code'], 'ERROR');
        }
    } catch (Exception $e) {
        log_msg("✗ Error accessing interfaces: " . $e->getMessage(), 'ERROR');
    }
    
    echo "\n";
    
    // Test 5: Parent interface check
    log_msg("Test 5: Parent Interface Check", 'INFO');
    log_msg(str_repeat('─', 50), 'INFO');
    
    try {
        if ($config['use_restconf']) {
            $result = tnsr_restconf_request('GET', 
                "/data/netgate-interface:interfaces-config/interface=" . 
                urlencode($config['parent_interface'])
            );
            
            if ($result['http_code'] === 200) {
                log_msg("✓ Parent interface '{$config['parent_interface']}' exists", 'SUCCESS');
                
                $ifData = $result['response']['netgate-interface:interface'][0] ?? null;
                if ($ifData) {
                    $enabled = $ifData['netgate-interface:enabled'] ?? false;
                    log_msg("  Status: " . ($enabled ? 'enabled' : 'disabled'), 
                        $enabled ? 'SUCCESS' : 'WARNING');
                    
                    if (isset($ifData['netgate-interface:interface']['netgate-interface:ipv4']['netgate-interface:address'])) {
                        $ipv4 = $ifData['netgate-interface:interface']['netgate-interface:ipv4']['netgate-interface:address'][0]['netgate-interface:ip'] ?? 'unknown';
                        log_msg("  IPv4: {$ipv4}", 'INFO');
                    }
                    
                    if (isset($ifData['netgate-interface:interface']['netgate-interface:ipv6']['netgate-interface:address'])) {
                        $ipv6 = $ifData['netgate-interface:interface']['netgate-interface:ipv6']['netgate-interface:address'][0]['netgate-interface:ip'] ?? 'unknown';
                        log_msg("  IPv6: {$ipv6}", 'INFO');
                    }
                }
            } else {
                log_msg("✗ Parent interface not found", 'ERROR');
                log_msg("  → Check 'parent_interface' setting in config", 'WARNING');
            }
        } else {
            $output = tnsr_ssh_command("show interface {$config['parent_interface']}");
            
            if (!strpos($output, 'not found') && !strpos($output, 'error')) {
                log_msg("✓ Parent interface exists", 'SUCCESS');
            } else {
                log_msg("✗ Parent interface not found", 'ERROR');
            }
        }
    } catch (Exception $e) {
        log_msg("✗ Error checking parent interface: " . $e->getMessage(), 'ERROR');
    }
    
    echo "\n";
    
    // Summary and recommendations
    log_msg("Diagnostic Summary", 'INFO');
    log_msg(str_repeat('═', 50), 'INFO');
    
    if ($config['dry_run']) {
        log_msg("⚠ DRY-RUN MODE IS ENABLED", 'WARNING');
        log_msg("  Set 'dry_run' => false to make actual changes", 'INFO');
        echo "\n";
    }
    
    log_msg("Next steps:", 'INFO');
    log_msg("  1. Fix any errors shown above", 'INFO');
    log_msg("  2. Try: php tnsr-vlan-restconf-FIXED.php list", 'INFO');
    log_msg("  3. Try: php tnsr-vlan-restconf-FIXED.php create 2602:f937:0:100::/56", 'INFO');
    echo "\n";
}

function interactive_test() {
    global $config;
    
    echo "\n";
    echo "╔════════════════════════════════════════════════════╗\n";
    echo "║      TNSR VLAN Sync - Interactive Test Mode       ║\n";
    echo "╚════════════════════════════════════════════════════╝\n";
    echo "\n";
    
    // Show configuration
    log_msg("Current Configuration:", 'INFO');
    log_msg("  TNSR Host:         {$config['tnsr_host']}", 'INFO');
    log_msg("  Parent Interface:  {$config['parent_interface']}", 'INFO');
    log_msg("  IPv6 Prefix:       {$config['ipv6_prefix']}", 'INFO');
    log_msg("  Method:            " . ($config['use_restconf'] ? 'RESTCONF' : 'SSH'), 'INFO');
    log_msg("  Dry Run:           " . ($config['dry_run'] ? 'YES' : 'NO'), 'INFO');
    echo "\n";
    
    // Prompt for subnet
    echo "Enter customer subnet (e.g., 2602:f937:0:100::/56): ";
    $subnet = trim(fgets(STDIN));
    
    if (empty($subnet)) {
        log_msg("No subnet provided, exiting", 'ERROR');
        return;
    }
    
    // Validate subnet format
    if (!preg_match('/^[0-9a-f:]+\/56$/i', $subnet)) {
        log_msg("Invalid subnet format", 'ERROR');
        return;
    }
    
    echo "\n";
    log_msg("Testing with subnet: {$subnet}", 'INFO');
    echo "\n";
    
    // Run tests
    $tests = [
        ['name' => 'Create subinterface', 'func' => 'create_subinterface'],
        ['name' => 'Verify configuration', 'func' => 'verify_subinterface'],
        ['name' => 'Delete subinterface', 'func' => 'delete_subinterface'],
    ];
    
    foreach ($tests as $test) {
        echo str_repeat('─', 60) . "\n";
        log_msg("Test: {$test['name']}", 'INFO');
        echo str_repeat('─', 60) . "\n";
        
        try {
            $test['func']($subnet);
            echo "\n";
            
            if ($test['func'] !== 'delete_subinterface') {
                echo "Press Enter to continue...";
                fgets(STDIN);
            }
        } catch (Exception $e) {
            log_msg("Test failed: " . $e->getMessage(), 'ERROR');
            echo "\n";
            echo "Continue anyway? (y/n): ";
            $continue = trim(fgets(STDIN));
            if (strtolower($continue) !== 'y') {
                return;
            }
        }
        
        echo "\n";
    }
    
    log_msg("Interactive test complete!", 'SUCCESS');
}

// ==================== MAIN ====================

if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line\n");
}

// Parse arguments
$command = $argv[1] ?? null;
$subnet = $argv[2] ?? null;

if (!$command) {
    show_usage();
    exit(1);
}

try {
    switch ($command) {
        case 'create':
            if (!$subnet) {
                log_msg("Error: Subnet required for create command", 'ERROR');
                show_usage();
                exit(1);
            }
            create_subinterface($subnet);
            break;
            
        case 'delete':
            if (!$subnet) {
                log_msg("Error: Subnet required for delete command", 'ERROR');
                show_usage();
                exit(1);
            }
            delete_subinterface($subnet);
            break;
            
        case 'verify':
            if (!$subnet) {
                log_msg("Error: Subnet required for verify command", 'ERROR');
                show_usage();
                exit(1);
            }
            $passed = verify_subinterface($subnet);
            exit($passed ? 0 : 1);
            break;
            
        case 'list':
            list_subinterfaces();
            break;
            
        case 'diagnose':
        case 'diagnostic':
        case 'diag':
            diagnose_connection();
            break;
            
        case 'test':
            interactive_test();
            break;
            
        default:
            log_msg("Error: Unknown command '{$command}'", 'ERROR');
            show_usage();
            exit(1);
    }
    
} catch (Exception $e) {
    log_msg("Fatal error: " . $e->getMessage(), 'ERROR');
    
    if ($config['verbose']) {
        log_msg("Stack trace:\n" . $e->getTraceAsString(), 'DEBUG');
    }
    
    exit(1);
}

exit(0);
