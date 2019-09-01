<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

use App\User;

use App\Utils\MetadataUtils;
use StackUtil\Utils\Utility;
use StackUtil\Utils\DbUtils;

use stdClass;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    public function register(Request $request)
    {
        try {
            $tableName = 'users';
            $metadata = MetadataUtils::CallMetaData($request, $tableName);
            $object = MetadataUtils::GetObject($metadata,$tableName);
            $id = Utility::generateId('s',$object['short_name']);
            $key = Utility::generateKey($object['short_name']);

            $user = User::create([
                'id'        =>  $id,
                'key'       =>  $key,
                'name'      =>  $request->name,
                'email'     =>  $request->email,
                'password'  =>  app('hash')->make($request->password, ['rounds' => 12]),
            ]);

            if(isset($user))
            {
                if(isset($request->responsibility_key)){

                    $responsibility = MetadataUtils::GetResponsibility($request, $request->responsibility_key);

                    if(isset($responsibility)){

                        $userResponsibilityMetadata = MetadataUtils::CallMetaData($request, 'user_responsibility');

                        $object = MetadataUtils::GetObject($userResponsibilityMetadata,'user_responsibility');

                        $user_responsibility = new stdClass();
                        $user_responsibility->id = Utility::generateId('s',$object['short_name']);
                        $user_responsibility->key = Utility::generateKey($object['short_name']);
                        $user_responsibility->name = $request->responsibility_key;
                        $user_responsibility->user_id = $id;
                        $user_responsibility->responsibility_id = $responsibility['id'];
                        $user_responsibility->active = 1;
                        $results = DbUtils::generateInsert('user_responsibility', json_decode(json_encode($user_responsibility), true));
                        $user->responsibility_id = $user_responsibility->id;
                    }
                }
                $getStatusCode = 201;
                AuthController::history($request, $user, $id, $getStatusCode);
            }
            return response()->json(['message'=> 'Registered Successfully.'],200);

          }
          catch(\Illuminate\Database\QueryException $ex)
          {
            $errorcode = strlen($ex->getCode()) == 3 ? $ex->getCode() : 500;
            return response()->json(['message'=>'SQL Exception',
            'error'=>$ex->getMessage(),
            'status'=>$ex->getCode(),
            'created_at'=> date("Y/m/d h:i:s"),
            'method'=>$request->method()
            ])
            ->setStatusCode($errorcode);;
          }
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = $request->only(['email', 'password']);

        if (!$token = Auth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }else{
            $result = Auth::user();
            
            $res = DbUtils::generateQuery('user_responsibility',null, 'all', "user_id=$result->id,active=1");
            $resArray = json_decode($res,true);
            if(!empty($resArray)){
                $result->responsibility_id = $resArray[0]['responsibility_id'];
                $customClaims = ['user_info'=> $result];
                $token = Auth::claims($customClaims)->login($result);
                $getStatusCode = 200;
                $result->token = $token;
                AuthController::history($request, $result, $result->id, $getStatusCode);
                return $this->respondWithToken($token);
            }else{
                // $token = Auth::login($result);
                return response()->json([
                        'status'=>'error',
                        'message' => '{'.$result->name.'} User is don\'t have any Responsibility',
                        'created' => gmdate("F j, Y, g:i a")
                    ],404);
            }
        }
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(Auth::user());
    }

    public function checkAuth(){
        return response()->json(Auth::user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        Auth::logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    // protected function respondWithToken($token)
    protected function respondWithToken($token)
    {
        $cookie = app()->make('cookie');
            // Set the refresh token as an encrypted HttpOnly cookie
            $cookie->queue('refreshToken',
                $token,
                604800, // expiration, should be moved to a config file
                null,
                null,
                true,
                true // HttpOnly
            );

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 3600
        ]);
    }

    public function history($request, $response = null , $userId, $getStatusCode)
    {
        if ( env('API_DATALOGGER', true) ) {
            $endTime = microtime(true);
            $tableName = 'history';
            $dataToLog['user_id'] = $userId;
            $dataToLog['name'] = 'User_Name';
            $dataToLog['time'] =  gmdate("F j, Y, g:i a");
            $dataToLog['duration'] =  number_format($endTime - LUMEN_START, 3);
            $dataToLog['ipaddress'] =  $request->ip();
            $dataToLog['url'] =    $request->fullUrl();
            $dataToLog['method'] = $request->method();
            $dataToLog['input'] =  $request->getContent();
            $dataToLog['output'] = $response;
            $dataToLog['status_code'] = $getStatusCode;
            $metadata = MetadataUtils::CallMetaData($response, $tableName);
            $object = MetadataUtils::GetObject($metadata,$tableName);
            $dataToLog['id'] = Utility::generateId('s',$object['short_name']);
            $dataToLog['key'] = Utility::generateKey($object['short_name']);
            $result = DbUtils::generateInsert($tableName,$dataToLog);
        }
    }

}
