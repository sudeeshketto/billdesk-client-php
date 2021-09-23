<?php

namespace io\billdesk\client;

class Response {
    private $responseStatus;
    private $response;
    private $bdTraceId;
    private $bdTimestamp;

    function __construct($responseStatus, $response, $bdTraceId, $bdTimestamp) {
        $this->responseStatus = $responseStatus;
        $this->response = $response;        
        $this->bdTraceId = $bdTraceId;
        $this->bdTimestamp = $bdTimestamp;
    }

    function getResponseStatus() {
        return $this->responseStatus;
    }

    function getResponse() {
        return $this->response;
    }

    function getBdTraceid() {
        return $this->bdTraceId;
    }

    function getBdTimestamp() {
        return $this->bdTimestamp;
    }
}