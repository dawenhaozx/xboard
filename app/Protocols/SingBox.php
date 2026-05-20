<?php
namespace App\Protocols;

use App\Utils\Helper;

class SingBox
{
    public $flag = 'sing-box,hiddify';
    private $servers;
    private $user;
    private $config;
    private $isLegacy; // true = 1.x, false = 2.x+

    public function __construct($user, $servers, array $options = null)
    {
        $this->user = $user;
        $this->servers = $servers;

        // 解析版本：1.12.x+ 为新版，1.11.x 为旧版，无法识别默认新版
        $version = $options['singbox_version'] ?? null;
        $this->isLegacy = $version
            ? version_compare($version, '1.12.0', '<')
            : false;
    }

    public function handle()
    {
        $appName = admin_setting('app_name', 'XBoard');
        $this->config = $this->loadConfig();
        $this->buildOutbounds();
        $this->buildRule();
        $user = $this->user;

        return response()
            ->json($this->config)
            ->header('profile-title', 'base64:' . base64_encode($appName))
            ->header('subscription-userinfo', "upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}")
            ->header('profile-update-interval', '24');
    }

    protected function loadConfig()
    {
        // 旧版 1.x 用 legacy 模板，新版 2.x+ 用默认模板
        // custom 优先级最高，且按版本区分
        if ($this->isLegacy) {
            $customConfig  = base_path('resources/rules/custom.sing-box-legacy.json');
            $defaultConfig = base_path('resources/rules/default.sing-box-legacy.json');
        } else {
            $customConfig  = base_path('resources/rules/custom.sing-box.json');
            $defaultConfig = base_path('resources/rules/default.sing-box.json');
        }

        $jsonData = file_exists($customConfig)
            ? file_get_contents($customConfig)
            : file_get_contents($defaultConfig);

        return json_decode($jsonData, true);
    }

    protected function buildOutbounds()
    {
        $outbounds = $this->config['outbounds'];
        $proxies = [];

        foreach ($this->servers as $item) {
            if ($item['type'] === 'shadowsocks') {
                $proxies[] = $this->buildShadowsocks($item['password'], $item);
            }
            if ($item['type'] === 'trojan') {
                $proxies[] = $this->buildTrojan($this->user['uuid'], $item);
            }
            if ($item['type'] === 'vmess') {
                $proxies[] = $this->buildVmess($this->user['uuid'], $item);
            }
            if ($item['type'] === 'vless') {
                $proxies[] = $this->buildVless($this->user['uuid'], $item);
            }
            if ($item['type'] === 'hysteria') {
                $proxies[] = $this->buildHysteria($this->user['uuid'], $item, $this->user);
            }
        }

        foreach ($outbounds as &$outbound) {
            if (in_array($outbound['type'], ['urltest', 'selector'])) {
                array_push($outbound['outbounds'], ...array_column($proxies, 'tag'));
            }
        }

        $this->config['outbounds'] = array_merge($outbounds, $proxies);
    }

    protected function buildRule()
    {
        $rules = $this->config['route']['rules'];

        $serverIps = collect($this->servers)
            ->pluck('host')
            ->map(function ($host) {
                return filter_var($host, FILTER_VALIDATE_IP)
                    ? [$host]
                    : Helper::getIpByDomainName($host);
            })
            ->flatten()
            ->unique()
            ->values()
            ->toArray();

        if ($this->isLegacy) {
            // 1.x：字段名为 ip_cidr
            array_unshift($rules, [
                'ip_cidr'  => $serverIps,
                'outbound' => 'direct',
            ]);
        } else {
            // 2.x+：ip_cidr 改为 ip_is_private 同级，字段名保持 ip_cidr
            // 但 rule_set 引用方式、action 字段等有变化
            array_unshift($rules, [
                'ip_cidr'  => $serverIps,
                'outbound' => 'direct',
            ]);
            // 2.x 新增：将 route.rules 里的 rule_set 引用由旧式 string[] 转为 object 格式
            // 这部分由模板文件自身处理，代码层无需额外转换
        }

        $this->config['route']['rules'] = $rules;
    }

    // ──────────────────────────────────────────
    // 以下 build* 方法按 isLegacy 做字段差异处理
    // ──────────────────────────────────────────

    protected function buildShadowsocks($password, $server)
    {
        return [
            'tag'         => $server['name'],
            'type'        => 'shadowsocks',
            'server'      => $server['host'],
            'server_port' => $server['port'],
            'method'      => $server['cipher'],
            'password'    => $password,
        ];
    }

    protected function buildVmess($uuid, $server)
    {
        $array = [
            'tag'         => $server['name'],
            'type'        => 'vmess',
            'server'      => $server['host'],
            'server_port' => $server['port'],
            'uuid'        => $uuid,
            'security'    => 'auto',
            'alter_id'    => 0,
            'transport'   => [],
        ];

        if ($server['tls']) {
            $tlsConfig = ['enabled' => true];
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                $tlsConfig['insecure']     = !empty($tlsSettings['allowInsecure']);
                $tlsConfig['server_name']  = $tlsSettings['serverName'] ?? null;
            }
            $array['tls'] = $tlsConfig;
        }

        if ($server['network'] === 'tcp') {
            $tcpSettings = $server['networkSettings'];
            if (isset($tcpSettings['header']['type']) && $tcpSettings['header']['type'] === 'http') {
                $array['transport']['type'] = 'http';
            }
            if (isset($tcpSettings['header']['request']['path'][0])) {
                $paths = $tcpSettings['header']['request']['path'];
                $array['transport']['path'] = $paths[array_rand($paths)];
            }
            if (isset($tcpSettings['header']['request']['headers']['Host'][0])) {
                $array['transport']['host'] = $tcpSettings['header']['request']['headers']['Host'];
            }
        }
        if ($server['network'] === 'ws') {
            $array['transport']['type'] = 'ws';
            if ($server['networkSettings']) {
                $ws = $server['networkSettings'];
                if (!empty($ws['path']))
                    $array['transport']['path'] = $ws['path'];
                if (!empty($ws['headers']['Host']))
                    $array['transport']['headers'] = ['Host' => [$ws['headers']['Host']]];
                $array['transport']['max_early_data']        = 2560;
                $array['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol';
            }
        }
        if ($server['network'] === 'grpc') {
            $array['transport']['type'] = 'grpc';
            if (!empty($server['networkSettings']['serviceName']))
                $array['transport']['service_name'] = $server['networkSettings']['serviceName'];
        }

        if (empty($array['transport'])) unset($array['transport']);
        return $array;
    }

    protected function buildVless($password, $server)
    {
        $array = [
            'type'             => 'vless',
            'tag'              => $server['name'],
            'server'           => $server['host'],
            'server_port'      => $server['port'],
            'uuid'             => $password,
            'packet_encoding'  => 'xudp',
        ];

        if ($server['tls']) {
            $tlsSettings = $server['tls_settings'] ?? [];
            $tlsConfig = ['enabled' => true];
            $array['flow'] = $server['flow'] ?? '';

            $tlsConfig['insecure']    = isset($tlsSettings['allow_insecure']) && $tlsSettings['allow_insecure'] == 1;
            $tlsConfig['server_name'] = $tlsSettings['server_name'] ?? null;

            if ($server['tls'] == 2) {
                $tlsConfig['reality'] = [
                    'enabled'    => true,
                    'public_key' => $tlsSettings['public_key'],
                    'short_id'   => $tlsSettings['short_id'],
                ];
            }

            $fingerprints = ['chrome', 'firefox', 'safari', 'ios', 'edge', 'qq'];
            $tlsConfig['utls'] = [
                'enabled'     => true,
                'fingerprint' => $fingerprints[array_rand($fingerprints)],
            ];

            $array['tls'] = $tlsConfig;
        }

        if ($server['network'] === 'tcp') {
            $tcpSettings = $server['network_settings'];
            if (isset($tcpSettings['header']['type']) && $tcpSettings['header']['type'] === 'http')
                $array['transport']['type'] = 'http';
            if (isset($tcpSettings['header']['request']['path']))
                $array['transport']['path'] = $tcpSettings['header']['request']['path'];
        }
        if ($server['network'] === 'ws') {
            $array['transport']['type'] = 'ws';
            if ($server['network_settings']) {
                $ws = $server['network_settings'];
                if (!empty($ws['path']))
                    $array['transport']['path'] = $ws['path'];
                if (!empty($ws['headers']['Host']))
                    $array['transport']['headers'] = ['Host' => [$ws['headers']['Host']]];
                $array['transport']['max_early_data']        = 2560;
                $array['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol';
            }
        }
        if ($server['network'] === 'grpc') {
            $array['transport']['type'] = 'grpc';
            if (!empty($server['network_settings']['serviceName']))
                $array['transport']['service_name'] = $server['network_settings']['serviceName'];
        }
        if ($server['network'] === 'h2') {
            $array['transport']['type'] = 'http';
            if ($server['network_settings']) {
                $h2 = $server['network_settings'];
                if (isset($h2['host']))  $array['transport']['host'] = [$h2['host']];
                if (isset($h2['path']))  $array['transport']['path'] = $h2['path'];
            }
        }

        return $array;
    }

    protected function buildTrojan($password, $server)
    {
        $array = [
            'tag'         => $server['name'],
            'type'        => 'trojan',
            'server'      => $server['host'],
            'server_port' => $server['port'],
            'password'    => $password,
            'tls'         => [
                'enabled'     => true,
                'insecure'    => !empty($server['allow_insecure']),
                'server_name' => $server['server_name'],
            ],
        ];

        if (isset($server['network']) && in_array($server['network'], ['grpc', 'ws'])) {
            $array['transport']['type'] = $server['network'];
            if ($server['network'] === 'grpc' && isset($server['network_settings']['serviceName']))
                $array['transport']['service_name'] = $server['network_settings']['serviceName'];
            if ($server['network'] === 'ws') {
                if (isset($server['network_settings']['path']))
                    $array['transport']['path'] = $server['network_settings']['path'];
                if (isset($server['network_settings']['headers']['Host']))
                    $array['transport']['headers'] = ['Host' => [$server['network_settings']['headers']['Host']]];
                $array['transport']['max_early_data']        = 2560;
                $array['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol';
            }
        }

        return $array;
    }

    protected function buildHysteria($password, $server, $user)
    {
        $array = [
            'server'      => $server['host'],
            'server_port' => $server['port'],
            'tls'         => [
                'enabled'     => true,
                'insecure'    => !empty($server['insecure']),
                'server_name' => $server['server_name'],
            ],
        ];

        if (is_null($server['version']) || $server['version'] == 1) {
            $array['tag']      = $server['name'];
            $array['type']     = 'hysteria';
            $array['auth_str'] = $password;
            $array['up_mbps']  = $user->speed_limit ? min($server['down_mbps'], $user->speed_limit) : $server['down_mbps'];
            $array['down_mbps'] = $user->speed_limit ? min($server['up_mbps'], $user->speed_limit) : $server['up_mbps'];
            if ($server['is_obfs'])
                $array['obfs'] = $server['server_key'];
            $array['disable_mtu_discovery'] = true;

        } elseif ($server['version'] == 2) {
            $array['tag']      = $server['name'];
            $array['type']     = 'hysteria2';
            $array['password'] = $password;
            $array['up_mbps']  = $user->speed_limit ? min($server['down_mbps'], $user->speed_limit) : $server['down_mbps'];
            $array['down_mbps'] = $user->speed_limit ? min($server['up_mbps'], $user->speed_limit) : $server['up_mbps'];
            if ($server['is_obfs']) {
                $array['obfs'] = [
                    'type'     => 'salamander',
                    'password' => $server['server_key'],
                ];
            }
        }

        return $array;
    }
}
