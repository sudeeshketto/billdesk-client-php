<?php declare(strict_types=1);

use io\billdesk\client\hmacsha256\BillDeskJWEHS256Client;
use io\billdesk\client\Logging;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use PHPUnit\Framework\TestCase;

class BillDeskJWSHS256ClientTest extends TestCase {
    private $client;
    private $log;

    protected function setUp(): void
    {
        Logging::addHandler(new StreamHandler('php://stdout', Logger::DEBUG));
        $this->client = new BillDeskJWEHS256Client("https://pguat.billdesk.io", "<your client id here>", "<Your hmac key here>");
    }
    
    public function testCreateOrder() {
        $request = array(
            'mercid' => "<your merchant id here>",
            'orderid' => uniqid(),
            'amount' => "1.0",
            'order_date' => date_format(new \DateTime(), DATE_W3C),
            'currency' => "356",
            'ru' => "https://www.billdesk.io",
            'itemcode' => "DIRECT",
            'device' => array(
                'init_channel' => 'internet',
                'ip' => "192.168.1.1",
                'user_agent' => 'Mozilla/5.0'
            )
        );

        $response = $this->client->createOrder($request);
        $this->assertEquals(200, $response->getResponseStatus());
    }
}