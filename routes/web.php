<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/


$router->get('/', function () use ($router) {
    return $router->app->version();
});

Route::group([

  // 'middleware' => 'api',
  'prefix' => 'auth/v1'

], function ($router) {
  Route::post('/RegisterUser', 'AuthController@register');
  Route::post('/login', 'AuthController@login');
  Route::post('/logout', 'AuthController@logout');
  Route::post('/refresh', 'AuthController@refresh');
  Route::post('/me', 'AuthController@me');
  Route::get('/authCheck','AuthController@checkAuth');
  // Route::get('/GetUser','AuthController@GetUser');

});