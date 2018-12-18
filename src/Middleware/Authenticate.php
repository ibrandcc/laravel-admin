<?php

namespace Encore\Admin\Middleware;

use Closure;
use Encore\Admin\Admin;
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
        $website = \Hyn\Tenancy\Facades\TenancyFacade::website();
        $cookie_key = 'ibrand_saas_sso_' . $website->uuid;
        if (!isset($_COOKIE[$cookie_key]) OR Auth::guard('admin')->guest()) {

            Auth::guard('admin')->logout();
            Auth::guard('account')->logout();
            $request->session()->flush();
            $request->session()->regenerate();

            return redirect('/account/login');
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
}
