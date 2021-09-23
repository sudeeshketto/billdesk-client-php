<?php

namespace io\billdesk\client\hmacsha256;

use DateTime;
use io\billdesk\client\BillDeskClient;
use io\billdesk\client\Response;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use io\billdesk\client\Constants;
use io\billdesk\client\Logging;
use Monolog\Logger;

class BillDeskJWEHS256Client implements BillDeskClient {
    private $pgBaseUrl;
    private $clientId;
    private $jweHelper;
    private static $logger;

    static function init() {
        self::$logger = Logging::getDefaultLogger();
    }

    public function __construct($baseUrl, $clientId, $merchantKey) {
        $this->pgBaseUrl = $baseUrl;
        $this->clientId = $clientId;
        $this->merchantKey = $merchantKey;
        $this->jweHelper = new JWEHS256Helper($merchantKey);
    }

    private function callPGApi($url, $request, $headers = array([])) {
        if (empty($headers[Constants::HEADER_BD_TRACE_ID])) {
            $headers[Constants::HEADER_BD_TRACE_ID] = uniqid();
        }

        $bdTraceid = $headers[Constants::HEADER_BD_TRACE_ID];

        if (empty($headers[Constants::HEADER_BD_TIMESTAMP])) {
            $headers[Constants::HEADER_BD_TIMESTAMP] = date_format(new DateTime(), 'YmdHis');
        }

        $bdTimestamp = $headers[Constants::HEADER_BD_TIMESTAMP];

        $headers["Content-Type"] = "application/jose";
        $headers["Accept"] = "application/jose";

        $requestJson = json_encode($request);
        
        self::$logger->info("Request to be sent to PG: " . $requestJson);
        
        $token = $this->jweHelper->encryptAndSign($requestJson, [
            Constants::JWE_HEADER_CLIENTID => $this->clientId
        ]);

        $method = "POST";

        self::$logger->info("Sending request to PG", array(
            "url" => $url,
            "method" => $method,
            "headers" => $headers,
            "body" => $token
        ));

        $client = new Client();
        $request = new Request($method, $url, $headers, $token);
        $response = $client->send($request);
        $responseToken = $response->getBody()->getContents();

        self::$logger->info("Response received from PG", array(
            "status" => $response->getStatusCode(),
            "body" => $responseToken
        ));
    
        $responseBody = $this->jweHelper->verifyAndDecrypt($responseToken);

        self::$logger->info("Decrypted response from PG: " . $responseBody);

        return new Response($response->getStatusCode(), json_decode($responseBody), $bdTraceid, $bdTimestamp);
    }

    public function createOrder($request, $headers = array()) {
        return $this->callPGApi(Constants::createOrderURL($this->pgBaseUrl), $request, $headers);
    }

    public function createTransaction($request, $headers = array()) {
        return $this->callPGApi(Constants::createTransactionURL($this->pgBaseUrl), $request, $headers);
    }

    public function refundTransaction($request, $headers = array()) {
        return $this->callPGApi(Constants::refundTransactionURL($this->pgBaseUrl), $request, $headers);
    }
}

BillDeskJWEHS256Client::init();
