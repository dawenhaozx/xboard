<?php
namespace App\Http\Routes\V1;

use Illuminate\Contracts\Routing\Registrar;

class ClientRoute
{
    public function map(Registrar $router)
    {
        $router->group([
            'prefix' => 'client',
            'middleware' => 'client'
        ], function ($router) {
            // Client
            if (empty(admin_setting('subscribe_path'))) {
                // 只有后台没配置自定义路径，才使用默认 /subscribe
                $router->get('/subscribe', 'V1\Client\ClientController@subscribe')->name('client.subscribe');
            }
            // App
            $router->get('/app/getConfig', 'V1\\Client\\AppController@getConfig');
            $router->get('/app/getVersion', 'V1\\Client\\AppController@getVersion');
        });
    }
}
