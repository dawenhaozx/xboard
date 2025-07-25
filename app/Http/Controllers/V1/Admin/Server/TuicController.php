<?php

namespace App\Http\Controllers\V1\Admin\Server;

use App\Http\Controllers\Controller;
use App\Models\ServerTuic;
use App\Utils\Helper;
use Illuminate\Http\Request;

class TuicController extends Controller
{
    public function save(Request $request)
    {
        $params = $request->validate([
            'show' => '',
            'name' => 'required',
            'group_id' => 'required|array',
            'route_id' => 'nullable|array',
            'parent_id' => 'nullable|integer',
            'host' => 'required',
            'port' => 'required',
            'server_port' => 'required',
            'tags' => 'nullable|array',
            'rate' => 'required|numeric',
            'server_name' => 'nullable',
            'insecure' => 'required|in:0,1',
            'disable_sni' => 'required|in:0,1',
            'udp_relay_mode' => 'nullable',
            'zero_rtt_handshake' => 'required|in:0,1',
            'congestion_control' => 'nullable'
        ]);

        if ($request->input('id')) {
            $server = ServerTuic::find($request->input('id'));
            if (!$server) {
                return $this->fail([400202, '服务器不存在']);
            }
            try {
                $server->update($params);
            } catch (\Exception $e) {
                \Log::error($e);
                return $this->fail([500, '保存失败']);
            }
            return $this->success(true);
        }
        ServerTuic::create($params);

        return $this->success(true);
    }

    public function drop(Request $request)
    {
        if ($request->input('id')) {
            $server = ServerTuic::find($request->input('id'));
            if (!$server) {
                return $this->fail([400202,'节点不存在']);
            }
        }
        return $this->success($server->delete());
    }

    public function update(Request $request)
    {
        $params = $request->validate([
            'show' => 'nullable|in:0,1',
        ]);

        $server = ServerTuic::find($request->input('id'));

        if (!$server) {
            return $this->fail([400202, '该服务器不存在']);
        }
        try {
            $server->update($params);
        } catch (\Exception $e) {
            \Log::error($e);
            return $this->fail([500, '保存失败']);
        }

        return $this->success(true);
    }

    public function copy(Request $request)
    {
        $server = ServerTuic::find($request->input('id'));
        $server->show = 0;
        if (!$server) {
            return $this->fail([400202, '该服务器不存在']);
        }
        ServerTuic::create($server->toArray());
        return $this->success(true);
    }
}
