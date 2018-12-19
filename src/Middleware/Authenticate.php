<?php

namespace Encore\Admin\Middleware;

use Closure;
use Encore\Admin\Admin;
use Encore\Admin\Auth\Database\Administrator;
use Hyn\Tenancy\Contracts\Repositories\HostnameRepository;
use Hyn\Tenancy\Repositories\WebsiteRepository;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;

class Authenticate
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if(config('admin.backend.scenario')=='normal' || !config('admin.backend.scenario'))
        {
            if (Auth::guard('admin')->guest() && !$this->shouldPassThrough($request)) {
                return redirect()->guest(admin_base_path('auth/login'));
            }

        }else{
            if (!$request->cookie('ibrand_log_uuid')) {
                return $this->unAuthenticateHandle($request);
            }

            $website = \Hyn\Tenancy\Facades\TenancyFacade::website();
            $current_uuid = $website->uuid;

            $uuid = $request->cookie('ibrand_log_uuid');
            $cookie_key = 'ibrand_log_sso_user';
            if (!$request->cookie($cookie_key) OR $uuid != $current_uuid) {
                return $this->unAuthenticateHandle($request);
            }

            $environment = app()->make(\Hyn\Tenancy\Environment::class);
            $environment->tenant($website);
            config(['database.default' => 'tenant']);

            if (Auth::guard('admin')->guest()) {
                $mobile = json_decode($request->cookie($cookie_key), true)['mobile'];
                $admin = Administrator::where('mobile', $mobile)->first();
                if ($admin) {
                    Auth::guard('admin')->login($admin);
                }else{
                    return $this->unAuthenticateHandle($request);
                }
            }
        }
        return $next($request);
    }

    /**
     * Determine if the request has a URI that should pass through verification.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return bool
     */
    protected function shouldPassThrough($request)
    {
        $excepts = [
            admin_base_path('auth/login'),
            admin_base_path('auth/logout'),
        ];

        foreach ($excepts as $except) {
            if ($except !== '/') {
                $except = trim($except, '/');
            }

            if ($request->is($except)) {
                return true;
            }
        }

        return false;
    }

    protected function unAuthenticateHandle($request)
    {
        Auth::guard('admin')->logout();
        $request->session()->flush();
        $request->session()->regenerate();

        Cookie::queue(Cookie::forget('ibrand_log_uuid'));
        Cookie::queue(Cookie::forget('ibrand_log_sso_user'));

        return redirect(env('APP_URL').'/account/login');
    }
}
