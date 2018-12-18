<?php

namespace Encore\Admin\Middleware;

use Closure;
use Encore\Admin\Admin;
use Encore\Admin\Auth\Database\Administrator;
use Illuminate\Support\Facades\Auth;

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
        if (!isset($_COOKIE['ibrand_log_uuid']) OR !$_COOKIE['ibrand_log_uuid']) {
            $this->unAuthenticateHandle($request);
        }

        $uuid = $_COOKIE['ibrand_log_uuid'];
        $cookie_key = 'ibrand_log_sso_user';

        $website = \Hyn\Tenancy\Facades\TenancyFacade::website();
        $current_uuid = $website->uuid;

        if (!isset($_COOKIE[$cookie_key]) OR
            !$_COOKIE[$cookie_key] OR
            $uuid != $current_uuid
        ) {
            $this->unAuthenticateHandle($request);
        }

        if (Auth::guard('admin')->guest()) {
            $mobile = json_encode($_COOKIE[$cookie_key], true)['mobile'];
            if ($admin = Administrator::where('mobile', $mobile)->first()) {
                Auth::guard('admin')->login($admin);
            }else{
                $this->unAuthenticateHandle($request);
            }
        }

        /*if (Auth::guard('admin')->guest() && !$this->shouldPassThrough($request)) {
            return redirect()->guest(admin_base_path('auth/login'));
        }*/

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
        Auth::guard('account')->logout();
        $request->session()->flush();
        $request->session()->regenerate();

        setcookie('ibrand_log_uuid', '', time() - 3600, '/', config('session.domain'), false, false);
        setcookie('ibrand_log_sso_user', '', time() - 3600, '/', config('session.domain'), false, false);

        return redirect('/account/login');
    }
}
