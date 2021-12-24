<?php

namespace io\billdesk\client\jose;

use Exception;

class SignatureVerificationException extends Exception {
    public function __construct($message) {
        parent::__construct($message);
    }
}