<?php

namespace App\Exceptions;

use Exception;
use Illuminate\Validation\ValidationException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Laravel\Lumen\Exceptions\Handler as ExceptionHandler;
use Symfony\Component\HttpKernel\Exception\HttpException;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that should not be reported.
     *
     * @var array
     */
    protected $dontReport = [
        AuthorizationException::class,
        HttpException::class,
        ModelNotFoundException::class,
        ValidationException::class,
    ];

    /**
     * Report or log an exception.
     *
     * This is a great spot to send exceptions to Sentry, Bugsnag, etc.
     *
     * @param  \Exception  $exception
     * @return void
     */
    public function report(Exception $exception)
    {
        parent::report($exception);
    }

    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Exception  $exception
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    public function render($request, Exception $exception)
    {
        if ($exception
        instanceof
        \Illuminate\Database\Eloquent\ModelNotFoundException)
        {

            return response()->json(['error'=>"Record {".$exception->getIds()[0]."} not found for object {".$exception->getModel()."}",
            'status'=>404,
            'created_at'=> date("Y/m/d h:i:s"),
            'method'=>$request->method(),
            'stack_trace'=>$exception->getTrace()
            ])
            ->setStatusCode(404);
        }else if($exception instanceof QueryException)
        {
            return response()->json(['error'=>$exception->getMessage(),
            'status'=>500,
            'created_at'=> date("Y/m/d h:i:s"),
            'method'=>$request->method(),
            'stack_trace'=>$exception->getTrace()
            ])
            ->setStatusCode(500);
        }else{
            $errorcode = strlen($exception->getCode()) == 3 ? $exception->getCode() : 500;
            return response()->json(['error'=>$exception->getMessage(),
            'status'=>$exception->getCode(),
            'created_at'=> date("Y/m/d h:i:s"),
            'method'=>$request->method(),
            'stack_trace'=>$exception->getTrace()

            ])
            ->setStatusCode($errorcode);
        }

        return parent::render($request, $exception);
    }
}
