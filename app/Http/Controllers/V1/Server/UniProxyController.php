<?php

namespace App\Http\Controllers\V1\Server;

use App\Http\Controllers\Controller;
use App\Services\ServerService;
use App\Services\UserService;
use App\Utils\CacheKey;
use App\Utils\Helper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;

class UniProxyController extends Controller
{

    // 后端获取用户
    public function user(Request $request)
    {
        ini_set('memory_limit', -1);
        Cache::put(CacheKey::get('SERVER_' . strtoupper($request->input('node_type')) . '_LAST_CHECK_AT', $request->input('node_id')), time(), 3600);
        $users = ServerService::getAvailableUsers($request->input('node_info')->group_id);
        Cache::put('ALIVE_USERS_' . $request->input('nodeType') . $request->input('nodeId'), $users, 3600); // 缓存 $users

        $response['users'] = $users->toArray();

        $eTag = sha1(json_encode($response));
        if (strpos($request->header('If-None-Match'), $eTag) !== false) {
            return response(null, 304);
        }

        return response($response)->header('ETag', "\"{$eTag}\"");
    }

    // 后端获取用户ips
    public function aips(Request $request)
    {
        ini_set('memory_limit', -1);
        $users = Cache::remember('ALIVE_USERS_' . $request->input('nodeType') . $request->input('nodeId'), now()->addMinutes(10), function () use ($request) {
            return ServerService::getAvailableUsers($request->input('node_info')->group_id);
        });
        $result = $users->map(function ($user) {
            $alive_ips = Cache::get('ALIVE_IP_USER_' . $user->id)['alive_ips'] ?? null;
            if ($user->device_limit !== null && $user->device_limit > 0 && $alive_ips !== null) {
                $alive_ips = array_slice($alive_ips, 0, $user->device_limit);
            }

            return [
                'id' => $user->id,
                'alive_ips' => $alive_ips,
            ];
        });
        $response['users'] = $result->toArray();
        $eTag = sha1(json_encode($response));
        if (strpos($request->header('If-None-Match'), $eTag) !== false) {
            return response(null, 304);
        }

        return response($response)->header('ETag', "\"{$eTag}\"");
    }

    // 后端提交数据
    public function push(Request $request)
    {
        $res = json_decode(get_request_content(), true);
        $data = Validator::make($res, [
            '*.0' => 'integer',
            '*.1' => 'integer',
        ])->validate();

        $nodeType = $request->input('node_type');
        $nodeId = $request->input('node_id');
        // 增加单节点多服务器统计在线人数
        $ip = $request->ip();
        $id = $request->input("id");
        $time = time();
        $cacheKey = CacheKey::get('MULTI_SERVER_' . strtoupper($nodeType) . '_ONLINE_USER', $nodeId);

        // 1、获取节点节点在线人数缓存
        $onlineUsers = Cache::get($cacheKey) ?? [];
        $onlineCollection = collect($onlineUsers);
        // 过滤掉超过600秒的记录
        $onlineCollection = $onlineCollection->reject(function ($item) use ($time) {
            return $item['time'] < ($time - 600);
        });
        // 定义数据
        $updatedItem = [
            'id' => $id ?? $ip,
            'ip' => $ip,
            'online_user' => count($data),
            'time' => $time
        ];

        $existingItemIndex = $onlineCollection->search(function ($item) use ($updatedItem) {
            return ($item['id'] ?? '') === $updatedItem['id'];
        });
        if ($existingItemIndex !== false) {
            $onlineCollection[$existingItemIndex] = $updatedItem;
        } else {
            $onlineCollection->push($updatedItem);
        }
        $onlineUsers = $onlineCollection->all();
        Cache::put($cacheKey, $onlineUsers, 3600);

        $online_user = $onlineCollection->sum('online_user');
        Cache::put(CacheKey::get('SERVER_' . strtoupper($nodeType) . '_ONLINE_USER', $nodeId), $online_user, 3600);
        Cache::put(CacheKey::get('SERVER_' . strtoupper($nodeType) . '_LAST_PUSH_AT', $nodeId), time(), 3600);
        $userService = new UserService();
        $userService->trafficFetch($request->input('node_info')->toArray(), $nodeType, $data, $ip);
        return $this->success(true);
    }

    // 后端获取配置
    public function config(Request $request)
    {
        $nodeType = $request->input('node_type');
        $nodeInfo = $request->input('node_info');
        switch ($nodeType) {
            case 'shadowsocks':
                $response = [
                    'server_port' => $nodeInfo->server_port,
                    'cipher' => $nodeInfo->cipher,
                    'obfs' => $nodeInfo->obfs,
                    'obfs_settings' => $nodeInfo->obfs_settings
                ];

                if ($nodeInfo->cipher === '2022-blake3-aes-128-gcm') {
                    $response['server_key'] = Helper::getServerKey($nodeInfo->created_at, 16);
                }
                if ($nodeInfo->cipher === '2022-blake3-aes-256-gcm') {
                    $response['server_key'] = Helper::getServerKey($nodeInfo->created_at, 32);
                }
                break;
            case 'vmess':
                $response = [
                    'server_port' => $nodeInfo->server_port,
                    'network' => $nodeInfo->network,
                    'networkSettings' => $nodeInfo->networkSettings,
                    'tls' => $nodeInfo->tls
                ];
                break;
            case 'trojan':
                $response = [
                    'host' => $nodeInfo->host,
                    'server_port' => $nodeInfo->server_port,
                    'server_name' => $nodeInfo->server_name,
                    'network' => $nodeInfo->network,
                    'networkSettings' => $nodeInfo->networkSettings,
                ];
                break;
            case 'hysteria':
                $response = [
                    'version' => $nodeInfo->version,
                    'host' => $nodeInfo->host,
                    'server_port' => $nodeInfo->server_port,
                    'server_name' => $nodeInfo->server_name,
                    'up_mbps' => $nodeInfo->up_mbps,
                    'down_mbps' => $nodeInfo->down_mbps,
                    'obfs' => $nodeInfo->is_obfs ? Helper::getServerKey($nodeInfo->created_at, 16) : null
                ];
                break;
            case "vless":
                $response = [
                    'server_port' => $nodeInfo->server_port,
                    'network' => $nodeInfo->network,
                    'network_settings' => $nodeInfo->network_settings,
                    'networkSettings' => $nodeInfo->network_settings,
                    'tls' => $nodeInfo->tls,
                    'flow' => $nodeInfo->flow,
                    'tls_settings' => $nodeInfo->tls_settings
                ];
                break;
        }
        $response['base_config'] = [
            'push_interval' => (int) admin_setting('server_push_interval', 60),
            'pull_interval' => (int) admin_setting('server_pull_interval', 60)
        ];
        if ($nodeInfo['route_id']) {
            $response['routes'] = ServerService::getRoutes($nodeInfo['route_id']);
        }
        $eTag = sha1(json_encode($response));
        if (strpos($request->header('If-None-Match'), $eTag) !== false) {
            return response(null, 304);
        }

        return response($response)->header('ETag', "\"{$eTag}\"");
    }

    public function alive(Request $request)
    {
        ini_set('memory_limit', -1);
        $requestData = json_decode(get_request_content(), true);
        $users = Cache::remember('ALIVE_USERS_' . $request->input('nodeType') . $request->input('nodeId'), now()->addMinutes(10), function () use ($request) {
            return ServerService::getAvailableUsers($request->input('node_info')->group_id);
        });

        $updateAt = time();
        // 构建需要更新的缓存数据
        $cacheData = [];
        $nodetypeid = $request->input('nodeType') . $request->input('nodeId');
        foreach ($users as $user) {
            $ipsData = $requestData[$user->id] ?? [];
            $ips_array = Cache::get('ALIVE_IP_USER_' . $user->id) ?? [];
            $allAliveIPs = [];
            // 更新节点数据
            if ($ipsData !== [] && $ips_array[$nodetypeid] !== []) {
                $ips_array[$nodetypeid] = ['aliveips' => $ipsData, 'lastupdateAt' => $updateAt];
                // 清理过期数据
                foreach ($ips_array as $nodetypeid => $oldips) {
                    if (!is_int($oldips) && ($updateAt - $oldips['lastupdateAt'] > 120)) {
                        unset($ips_array[$nodetypeid]);
                    } else if (!is_int($oldips) && isset($oldips['aliveips'])) {
                        $allAliveIPs = array_merge($allAliveIPs, $oldips['aliveips']);
                    }
                }
            }
            // 对同一用户的IP进行去重
            $aliveIps = array_unique($allAliveIPs);

            $ips_array['alive_ips'] = $aliveIps;
            $ips_array['alive_ip'] = count($aliveIps);

            $cacheData['ALIVE_IP_USER_' . $user->id] = $ips_array;
        }

        // 批量写入缓存
        Cache::putMany($cacheData, 135);

        return $this->success(true);
    }
}
